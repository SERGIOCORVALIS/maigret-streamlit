import asyncio
import io
import logging
import os
import re
import sys
import tempfile
from datetime import datetime

import streamlit as st

import maigret
import maigret.settings
from maigret.checking import build_cloudflare_bypass_config
from maigret.report import (
    generate_csv_report,
    generate_json_report,
    generate_report_context,
    save_graph_report,
    save_html_report,
)
from maigret.result import MaigretCheckStatus
from maigret.sites import MaigretDatabase
from maigret.utils import is_country_tag

import lookup_helpers as lookup

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

DB_FILE = os.path.join(os.path.dirname(maigret.__file__), 'resources', 'data.json')

# Streamlit Community Cloud gives ~1 GB RAM and shared egress; a full scan of
# every site with high concurrency is likely to get the app killed.
MAX_USERNAMES = 5
MAX_CONNECTIONS = int(os.getenv('MAIGRET_MAX_CONNECTIONS', '50'))
TOP_SITES_CHOICES = [100, 300, 500, 1000, 2000]

REGION_TAGS = {'ru', 'by', 'kz'}
# Not a country, but is_country_tag() treats it as one.
NEUTRAL_COUNTRY_TAGS = {'global'}
MODE_REGION = 'Россия и СНГ'
MODE_WORLD = 'Весь мир'

KIND_USERNAME = 'Username'
KIND_EMAIL = 'Email'
KIND_PHONE = 'Телефон'
KIND_NAME = 'ФИО'

st.set_page_config(page_title='Maigret OSINT', page_icon='🕵️', layout='wide')


@st.cache_resource(show_spinner='Загрузка базы сайтов…')
def load_db() -> MaigretDatabase:
    return MaigretDatabase().load_from_path(DB_FILE)


@st.cache_resource
def load_cf_bypass_config():
    settings = maigret.settings.Settings()
    settings.load()
    return build_cloudflare_bypass_config(settings)


@st.cache_data(ttl=3600, show_spinner='Запрос профиля Gravatar…')
def cached_gravatar(email):
    return lookup.gravatar_profile(email)


def show_links(links):
    st.dataframe(
        [{'Где': k, 'Ссылка': v} for k, v in links.items()],
        hide_index=True,
        width='stretch',
        column_config={'Ссылка': st.column_config.LinkColumn('Ссылка')},
    )


class StreamlitNotify:
    """query_notify shim that drives a Streamlit progress bar and live list."""

    def __init__(self, username, total, progress, found_box):
        self.username = username
        self.total = max(total, 1)
        self.checked = 0
        self.progress = progress
        self.found_box = found_box
        self.found = []
        # Streamlit signals a rerun/stop by raising a BaseException from st.*
        # calls. Inside maigret's worker tasks that exception only kills the
        # worker (the executor catches Exception, not BaseException), so the
        # search would "finish" with partial results. Keep it to re-raise
        # once maigret.search() returns.
        self.interrupted = None

    def update(self, result, is_similar=False):
        if self.interrupted is not None:
            raise self.interrupted
        self.checked += 1
        try:
            if result.status == MaigretCheckStatus.CLAIMED and not is_similar:
                self.found.append(f'- **{result.site_name}**: {result.site_url_user}')
                self.found_box.markdown('\n'.join(self.found))
            self.progress.progress(
                min(self.checked / self.total, 1.0),
                text=f'{self.username}: {self.checked}/{self.total} — {result.site_name}',
            )
        except Exception:
            raise
        except BaseException as e:
            self.interrupted = e
            raise

    def start(self, message=None, id_type='username'):
        pass

    def finish(self, message=None):
        pass

    def warning(self, *a, **k):
        pass

    def info(self, *a, **k):
        pass

    def success(self, *a, **k):
        pass

    def enrich(self, *a, **k):
        pass


def site_region(site) -> str:
    """'region' for RU/CIS sites, 'intl' for sites without a country, else 'foreign'."""
    countries = {t for t in site.tags if is_country_tag(t)} - NEUTRAL_COUNTRY_TAGS
    if countries & REGION_TAGS:
        return 'region'
    return 'foreign' if countries else 'intl'


def plan_search_parts(db, mode, top_sites, include_intl, tags, excluded_tags):
    """Return [(title, sites_dict), ...] — one entry per sequential search part."""
    candidates = db.ranked_sites_dict(
        tags=tags, excluded_tags=excluded_tags, disabled=False, id_type='username'
    )
    if mode == MODE_WORLD:
        return [('Все сайты', dict(list(candidates.items())[:top_sites]))]

    regional = {n: s for n, s in candidates.items() if site_region(s) == 'region'}
    parts = [('Часть 1: сайты России и СНГ', regional)]
    if include_intl:
        intl = [(n, s) for n, s in candidates.items() if site_region(s) == 'intl']
        parts.append(('Часть 2: международные сайты', dict(intl[:top_sites])))
    return [(title, sites) for title, sites in parts if sites]


def parse_usernames(raw: str):
    seen = []
    for u in re.split(r'[\s,]+', raw.strip()):
        u = u.lstrip('@')
        if u and u not in seen:
            seen.append(u)
    return seen


def run_search(username, sites, options, notify):
    logger = logging.getLogger('maigret')
    logger.setLevel(logging.WARNING)
    results = asyncio.run(
        maigret.search(
            username=username,
            site_dict=sites,
            logger=logger,
            id_type='username',
            query_notify=notify,
            no_progressbar=True,
            timeout=options['timeout'],
            max_connections=MAX_CONNECTIONS,
            is_parsing_enabled=options['extract_info'],
            recursive_search_enabled=False,
            check_domains=False,
            proxy=options['proxy'] or None,
            cloudflare_bypass=load_cf_bypass_config(),
        )
    )
    if notify.interrupted is not None:
        raise notify.interrupted
    return results


def claimed_rows(results):
    rows = []
    for site_name, data in results.items():
        status = data.get('status')
        if not status or status.status != MaigretCheckStatus.CLAIMED:
            continue
        ids = {
            k: v
            for k, v in (status.ids_data or {}).items()
            if k != '_extractor' and isinstance(v, (str, int, float))
        }
        rows.append(
            {
                'Сайт': site_name,
                'URL': data.get('url_user', ''),
                'Теги': ', '.join(status.tags or []),
                'Доп. данные': ', '.join(f'{k}: {v}' for k, v in ids.items()),
            }
        )
    return rows


def render_csv(username, results):
    buf = io.StringIO()
    generate_csv_report(username, results, buf)
    return buf.getvalue()


def render_file_report(fn, *args, suffix='.html'):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        fn(path, *args)
        with open(path, encoding='utf-8') as f:
            return f.read()
    finally:
        os.remove(path)


st.title('🕵️ Maigret')
st.caption(
    'Поиск аккаунтов по username, email, телефону и ФИО · '
    f'maigret {maigret.__version__}'
)

db = load_db()
all_tags = sorted({t for s in db.sites for t in s.tags})

with st.sidebar:
    st.header('Параметры')
    mode = st.radio(
        'Регион',
        [MODE_REGION, MODE_WORLD],
        help=(
            f'«{MODE_REGION}»: сначала проверяются все сайты с тегами '
            f'{", ".join(sorted(REGION_TAGS))}, затем международные. Сайты, '
            'привязанные только к другим странам, пропускаются.'
        ),
    )
    include_intl = True
    if mode == MODE_REGION:
        include_intl = st.checkbox('Часть 2: международные сайты', value=True)
    top_sites = st.select_slider(
        'Лимит международных сайтов' if mode == MODE_REGION else 'Количество сайтов',
        TOP_SITES_CHOICES,
        value=500,
        disabled=not include_intl,
        key='top_sites',
    )
    timeout = st.slider('Таймаут запроса, сек', 3, 30, 10)
    tags = st.multiselect('Только теги', all_tags)
    excluded_tags = st.multiselect('Исключить теги', all_tags)
    extract_info = st.checkbox('Извлекать данные со страниц профилей', value=True)
    proxy = st.text_input('Прокси (необязательно)', placeholder='socks5://host:port')
    st.divider()
    st.caption(
        'Используйте инструмент только в законных целях и с уважением к '
        'приватности людей.'
    )

kind = st.radio(
    'Что ищем', [KIND_USERNAME, KIND_EMAIL, KIND_PHONE, KIND_NAME], horizontal=True
)

# Email and full name are reduced to username candidates the user can edit
# before searching; a phone number only gets metadata and manual-check links.
candidates = []
lookup_info = {}
query_label = ''
if kind == KIND_USERNAME:
    raw_usernames = st.text_input(
        'Username(ы)', placeholder='soxoj, john_doe', help='Через пробел или запятую'
    )
    candidates = parse_usernames(raw_usernames)

elif kind == KIND_EMAIL:
    email = st.text_input('Email', placeholder='ivan.petrov@mail.ru').strip()
    if email and not lookup.is_valid_email(email):
        st.error('Некорректный email.')
    elif email:
        query_label = f'email {email}'
        candidates = lookup.email_local_candidates(email)
        gravatar_failed = False
        try:
            profile = cached_gravatar(email)
        except Exception as e:
            profile = None
            gravatar_failed = True
            st.warning(f'Не удалось проверить Gravatar: {e}')
        if profile:
            candidates += lookup.gravatar_usernames(profile)
            lookup_info['Gravatar'] = {
                k: profile.get(k)
                for k in ('display_name', 'profile_url', 'location', 'job_title',
                          'company', 'description', 'verified_accounts')
                if profile.get(k)
            }
        elif not gravatar_failed:
            st.caption('Публичного профиля Gravatar для этого адреса нет.')

elif kind == KIND_PHONE:
    raw_phone = st.text_input('Номер телефона', placeholder='+7 999 123-45-67')
    if raw_phone:
        number = lookup.parse_phone(raw_phone)
        if number is None:
            st.error('Номер не распознан. Укажите его с кодом страны, например +7…')
        else:
            st.subheader('Сведения о номере')
            st.table(lookup.phone_info(number))
            st.subheader('Ручная проверка')
            show_links(lookup.phone_links(number))
            st.caption(
                'Сайты не раскрывают, на какие аккаунты зарегистрирован номер, '
                'поэтому автоматический поиск по телефону не выполняется. '
                'Telegram и WhatsApp покажут профиль, только если владелец '
                'разрешил поиск по номеру.'
            )

elif kind == KIND_NAME:
    c1, c2, c3 = st.columns(3)
    last = c1.text_input('Фамилия').strip()
    first = c2.text_input('Имя').strip()
    middle = c3.text_input('Отчество (необязательно)').strip()
    if last and first:
        query_label = 'ФИО ' + ' '.join(p for p in (last, first, middle) if p)
        candidates = lookup.name_to_usernames(last, first, middle)
        st.subheader('Поиск по ФИО вручную')
        show_links(lookup.name_links(last, first, middle))
        st.caption(
            'Совпадения по username, полученным из ФИО, часто принадлежат '
            'однофамильцам — проверяйте найденные профили вручную.'
        )
    elif last or first:
        st.info('Укажите и фамилию, и имя.')

if lookup_info:
    for title, info in lookup_info.items():
        with st.expander(title, expanded=True):
            st.json(info)

usernames = []
submitted = False
if kind != KIND_PHONE:
    candidates = list(dict.fromkeys(candidates))
    if kind == KIND_USERNAME:
        usernames = candidates
        query_label = 'username ' + ', '.join(usernames)
    elif query_label:
        usernames = st.multiselect(
            'Варианты username для проверки',
            options=candidates,
            default=candidates[: min(3, MAX_USERNAMES)],
            max_selections=MAX_USERNAMES,
            accept_new_options=True,
            help='Можно убрать лишние варианты или добавить свои.',
        )

    # Not disabled while the input is empty: a click right after typing would
    # land on the still-disabled button and be lost.
    submitted = st.button('Искать', type='primary')
    if submitted and not usernames:
        st.error('Нечего искать: укажите данные для поиска.')
        submitted = False


def build_search_report(general_results, query_label):
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report = {'query': query_label, 'stamp': stamp, 'users': [], 'files': {}}
    for username, _, results in general_results:
        safe = re.sub(r'[^\w.-]', '_', username)
        json_buf = io.StringIO()
        generate_json_report(username, results, json_buf, 'ndjson')
        report['users'].append(
            {
                'username': username,
                'rows': claimed_rows(results),
                'csv': (render_csv(username, results), f'maigret_{safe}_{stamp}.csv'),
                'json': (json_buf.getvalue(), f'maigret_{safe}_{stamp}.ndjson'),
            }
        )
    builders = {
        'HTML-отчёт (все username)': (
            lambda: render_file_report(
                save_html_report, generate_report_context(general_results)
            ),
            f'maigret_report_{stamp}.html',
        ),
        'Граф связей (HTML)': (
            lambda: render_file_report(save_graph_report, general_results, db),
            f'maigret_graph_{stamp}.html',
        ),
    }
    for label, (build, file_name) in builders.items():
        try:
            report['files'][label] = (build(), file_name)
        except Exception as e:
            logging.getLogger('maigret').error(f'{label} failed: {e}')
    return report


if submitted:
    if len(usernames) > MAX_USERNAMES:
        st.warning(f'За один запуск обрабатываются первые {MAX_USERNAMES} username.')
        usernames = usernames[:MAX_USERNAMES]

    parts = plan_search_parts(
        db, mode, top_sites, include_intl, tags, excluded_tags
    )
    if not parts:
        st.error('Под выбранные фильтры не попал ни один сайт.')
        st.stop()

    options = {'timeout': timeout, 'extract_info': extract_info, 'proxy': proxy}
    general_results = []
    for username in usernames:
        results = {}
        for title, sites in parts:
            with st.status(
                f'«{username}» — {title} ({len(sites)} сайтов)…', expanded=True
            ):
                progress = st.progress(0.0)
                found_box = st.empty()
                notify = StreamlitNotify(username, len(sites), progress, found_box)
                try:
                    results.update(run_search(username, sites, options, notify))
                except Exception as e:
                    st.exception(e)
        if results:
            general_results.append((username, 'username', results))

    if general_results:
        with st.spinner('Формирование отчётов…'):
            st.session_state['search'] = build_search_report(general_results, query_label)
    else:
        st.session_state.pop('search', None)
        st.error('Поиск не дал результатов: все проверки завершились ошибкой.')

report = st.session_state.get('search')
if report:
    st.header('Результаты')
    st.caption(f'Запрос: {report["query"]}')

    for user in report['users']:
        rows = user['rows']
        st.subheader(f'{user["username"]} — найдено {len(rows)}')
        if rows:
            st.dataframe(
                rows,
                width='stretch',
                hide_index=True,
                column_config={'URL': st.column_config.LinkColumn('URL')},
            )
        else:
            st.info('Аккаунты не найдены.')

        c1, c2 = st.columns(2)
        for col, key, label, mime in (
            (c1, 'csv', 'CSV', 'text/csv'),
            (c2, 'json', 'JSON (ndjson)', 'application/x-ndjson'),
        ):
            data, file_name = user[key]
            col.download_button(
                label, data, file_name=file_name, mime=mime,
                key=f'{key}_{user["username"]}',
            )

    # Reports carry text scraped from third-party pages, so they are offered as
    # downloads rather than rendered inside the app's origin.
    st.divider()
    for col, (label, (data, file_name)) in zip(
        st.columns(2), report['files'].items()
    ):
        col.download_button(label, data, file_name=file_name, mime='text/html')

