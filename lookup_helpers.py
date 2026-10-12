"""Turn an email, phone number or full name into things maigret can search for.

Maigret itself only checks usernames, so email and full-name lookups are
reduced to a ranked list of username candidates. Phone numbers get offline
metadata plus links for manual checks: there is no public, non-abusive way to
test which sites a number is registered on.
"""

import hashlib
import re
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

import phonenumbers
import requests
from phonenumbers import carrier, geocoder, timezone

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{1,38}[a-z0-9_]$')

_COMMON = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e',
    'з': 'z', 'и': 'i', 'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o',
    'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'ы': 'y',
    'э': 'e', 'ь': '', 'ж': 'zh', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch',
    # Ukrainian, Belarusian and Kazakh letters, so CIS names don't lose them.
    'і': 'i', 'ї': 'yi', 'є': 'ye', 'ґ': 'g', 'ў': 'u', 'ә': 'a', 'ғ': 'g',
    'қ': 'k', 'ң': 'n', 'ө': 'o', 'ұ': 'u', 'ү': 'u', 'һ': 'h',
}
TRANSLIT_SCHEMES = {
    # What most people type by hand.
    'popular': {**_COMMON, 'й': 'y', 'х': 'kh', 'ц': 'ts', 'ъ': '', 'ю': 'yu', 'я': 'ya'},
    # Russian international passports since 2013 (ICAO Doc 9303).
    'icao': {**_COMMON, 'й': 'i', 'х': 'kh', 'ц': 'ts', 'ъ': 'ie', 'ю': 'iu', 'я': 'ia'},
    'simple': {**_COMMON, 'й': 'j', 'х': 'h', 'ц': 'c', 'ъ': '', 'ю': 'ju', 'я': 'ja',
               'щ': 'sch'},
}


def transliterate(text: str, scheme: str) -> str:
    table = TRANSLIT_SCHEMES[scheme]
    out = ''.join(table.get(ch, ch) for ch in text.strip().lower())
    return re.sub(r'[^a-z0-9]', '', out)


def name_to_usernames(last: str, first: str, middle: str = '') -> List[str]:
    """Username candidates for a full name, most likely first."""
    variants = []
    for scheme in TRANSLIT_SCHEMES:
        l, f, m = (transliterate(x, scheme) for x in (last, first, middle))
        if l and f:
            variants.append((l, f, m))
    if not variants:
        return []

    def patterns(l, f, m):
        yield f + l
        yield f'{f}.{l}'
        yield f'{f}_{l}'
        yield l + f
        yield f'{l}.{f}'
        yield f'{l}_{f}'
        yield f[0] + l
        yield f'{f[0]}.{l}'
        yield l + f[0]
        if m:
            yield f[0] + m[0] + l
            yield l + f[0] + m[0]
        yield f'{f}-{l}'
        yield f'{l}-{f}'
        yield l

    # Interleave schemes pattern by pattern so the top of the list mixes them.
    generators = [patterns(*v) for v in variants]
    seen: List[str] = []
    while generators:
        for gen in list(generators):
            candidate = next(gen, None)
            if candidate is None:
                generators.remove(gen)
            elif candidate not in seen and USERNAME_RE.match(candidate):
                seen.append(candidate)
    return seen


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email.strip()))


def email_local_candidates(email: str) -> List[str]:
    local = email.strip().lower().split('@', 1)[0]
    local = local.split('+', 1)[0]
    candidates = [local]
    if '.' in local:
        candidates += [local.replace('.', ''), local.replace('.', '_')]
    return [c for c in dict.fromkeys(candidates) if USERNAME_RE.match(c)]


def gravatar_profile(email: str, timeout: int = 10) -> Optional[Dict]:
    """Public Gravatar profile for the email, or None if there is none.

    Raises on network errors and rate limiting, so callers can tell "no
    profile" apart from "could not check".
    """
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    resp = requests.get(
        f'https://api.gravatar.com/v3/profiles/{digest}',
        headers={'User-Agent': 'maigret'},
        timeout=timeout,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def gravatar_usernames(profile: Dict) -> List[str]:
    urls = [profile.get('profile_url', '')]
    urls += [a.get('url', '') for a in profile.get('verified_accounts') or []]
    names = []
    for url in urls:
        segment = urlparse(url).path.strip('/').split('/')[-1].lstrip('@').lower()
        if USERNAME_RE.match(segment):
            names.append(segment)
    return list(dict.fromkeys(names))


def parse_phone(raw: str, default_region: str = 'RU'):
    """Parsed number, or None if it is not a valid phone number."""
    digits = re.sub(r'[^\d+]', '', raw)
    if default_region == 'RU' and re.fullmatch(r'8\d{10}', digits):
        digits = '+7' + digits[1:]
    try:
        number = phonenumbers.parse(digits, default_region)
    except phonenumbers.NumberParseException:
        return None
    return number if phonenumbers.is_valid_number(number) else None


def phone_info(number) -> Dict[str, str]:
    fmt = phonenumbers.PhoneNumberFormat
    return {
        'E.164': phonenumbers.format_number(number, fmt.E164),
        'Международный формат': phonenumbers.format_number(number, fmt.INTERNATIONAL),
        'Страна': phonenumbers.region_code_for_number(number) or '',
        'Регион': geocoder.description_for_number(number, 'ru'),
        'Оператор (исходный, без учёта переноса номера)': carrier.name_for_number(number, 'ru'),
        'Часовые пояса': ', '.join(timezone.time_zones_for_number(number)),
    }


def phone_formats(number) -> List[str]:
    """Spellings of the number commonly found in ads, profiles and documents."""
    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    national = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)
    intl = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    formats = [e164, e164[1:], intl, national]
    if number.country_code == 7:
        formats.append('8' + str(number.national_number))
    return list(dict.fromkeys(formats))


def phone_links(number) -> Dict[str, str]:
    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    query = ' | '.join(f'"{f}"' for f in phone_formats(number))
    return {
        'Telegram': f'https://t.me/{e164}',
        'WhatsApp': f'https://wa.me/{e164[1:]}',
        'Поиск в Яндексе': f'https://yandex.ru/search/?text={quote(query)}',
        'Поиск в Google': f'https://www.google.com/search?q={quote(query.replace(" | ", " OR "))}',
    }


def name_links(last: str, first: str, middle: str = '') -> Dict[str, str]:
    full = ' '.join(p for p in (last, first, middle) if p).strip()
    short = f'{first} {last}'.strip()
    return {
        'Поиск в Яндексе': f'https://yandex.ru/search/?text={quote(chr(34) + full + chr(34))}',
        'Поиск в Google': f'https://www.google.com/search?q={quote(chr(34) + full + chr(34))}',
        'Люди ВКонтакте': f'https://vk.com/search/people?q={quote(short)}',
        'Люди в Одноклассниках': f'https://ok.ru/search?st.mode=Users&st.query={quote(short)}',
    }
