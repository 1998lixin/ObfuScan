#!/usr/bin/env python3
import os
import subprocess
import json
import tempfile
import re
import shutil
import socket
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import cgi


def env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def env_flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


# 默认仅允许本机访问。公网部署应由 Caddy/Nginx 等反向代理提供 HTTPS、鉴权和限流。
HOST = os.environ.get('OBFUSCAN_HOST', '127.0.0.1').strip() or '127.0.0.1'
PORT = env_int('OBFUSCAN_PORT', 8080, 1, 65535)
UPLOAD_CHUNK_BYTES = 1024 * 1024
MAX_UPLOAD_BYTES = env_int('OBFUSCAN_MAX_UPLOAD_BYTES', 512 * 1024 * 1024,
                           1 * 1024 * 1024, 4 * 1024 * 1024 * 1024)
SCAN_TIMEOUT_SECONDS = env_int('OBFUSCAN_SCAN_TIMEOUT_SECONDS', 15 * 60, 10, 24 * 60 * 60)
MAX_SCANNER_STDOUT_BYTES = env_int('OBFUSCAN_MAX_SCANNER_STDOUT_BYTES',
                                   32 * 1024 * 1024, 1 * 1024 * 1024,
                                   256 * 1024 * 1024)
MAX_SCANNER_STDERR_BYTES = env_int('OBFUSCAN_MAX_SCANNER_STDERR_BYTES',
                                   1 * 1024 * 1024, 64 * 1024,
                                   16 * 1024 * 1024)
REQUEST_IDLE_TIMEOUT_SECONDS = env_int('OBFUSCAN_REQUEST_IDLE_TIMEOUT_SECONDS', 30, 5, 300)
MAX_ACTIVE_CONNECTIONS = env_int('OBFUSCAN_MAX_ACTIVE_CONNECTIONS', 32, 2, 256)
MAX_CONCURRENT_SCANS = env_int('OBFUSCAN_MAX_CONCURRENT_SCANS', 2, 1, 16)
MIN_FREE_DISK_RESERVE_BYTES = env_int('OBFUSCAN_MIN_FREE_DISK_RESERVE_BYTES',
                                      512 * 1024 * 1024, 64 * 1024 * 1024,
                                      16 * 1024 * 1024 * 1024)
EXPOSE_ENGINE_PATH = env_flag(
    'OBFUSCAN_EXPOSE_ENGINE_PATH',
    HOST in {'127.0.0.1', '::1', 'localhost'},
)
SCAN_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)

# LibChecker 规则库
# 动态获取当前 Python 脚本所在的目录，并拼接上 LibChecker-Rules 文件夹
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
LIBCHECKER_RULES_DIR = os.path.join(CURRENT_DIR, 'LibChecker-Rules')


def is_compatible_obfuscan_executable(path):
    """拒绝当前平台不可执行的产物，避免健康检查假报就绪。"""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, 'rb') as executable_file:
            magic = executable_file.read(2)
    except OSError:
        return False
    if os.name == 'nt':
        return magic == b'MZ'
    return magic != b'MZ' and os.access(path, os.X_OK)


def resolve_obfuscan_executable():
    """按可信优先级选择当前平台的扫描引擎，仓库根产物仅作回退。"""
    configured = os.environ.get('OBFUSCAN_EXECUTABLE', '').strip().strip('"')
    candidates = []
    if configured:
        candidates.append(('environment', os.path.abspath(os.path.expanduser(configured))))
    executable_name = 'ObfuScan.exe' if os.name == 'nt' else 'ObfuScan'
    candidates.extend([
        ('standard-release-build', os.path.join(CURRENT_DIR, 'build', 'Release', executable_name)),
        ('standard-build', os.path.join(CURRENT_DIR, 'build', executable_name)),
        ('cmake-build-release', os.path.join(CURRENT_DIR, 'cmake-build-release', executable_name)),
        ('cmake-build-release', os.path.join(CURRENT_DIR, 'cmake-build-release', 'Release', executable_name)),
        ('build-codex', os.path.join(CURRENT_DIR, 'build-codex', executable_name)),
        ('build-codex', os.path.join(CURRENT_DIR, 'build-codex', 'Release', executable_name)),
        ('repository-root-fallback', os.path.join(CURRENT_DIR, executable_name)),
    ])

    for source, path in candidates:
        if is_compatible_obfuscan_executable(path):
            return os.path.abspath(path), source
    return None, 'not-found'


def describe_engine(executable, source):
    if executable and not EXPOSE_ENGINE_PATH:
        visible_path = os.path.basename(executable)
    else:
        visible_path = executable or ''
    return {'path': visible_path, 'source': source}


class LibCheckerMatcher:
    """LibChecker 规则匹配器"""

    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = []
        self.load_rules()

    def load_rules(self):
        native_dir = os.path.join(self.rules_dir, 'native-libs')
        if not os.path.exists(native_dir):
            print(f"[警告] LibChecker 规则目录未找到: {native_dir}")
            return

        count = 0
        for filename in os.listdir(native_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(native_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        raw_rule = json.load(f)

                        # 初始化一个扁平化的规则字典
                        parsed_rule = {
                            '_filename': filename[:-5],  # e.g. libImSDK.so
                            'name': raw_rule.get('name'),
                            'isRegex': raw_rule.get('isRegex', False),
                            'label': '',
                            'team': '',
                            'description': ''
                        }

                        # 深入解析 LibChecker 的嵌套多语言结构
                        if 'data' in raw_rule and isinstance(raw_rule['data'], list):
                            zh_data = None
                            en_data = None

                            # 遍历寻找中文和英文
                            for lang_item in raw_rule['data']:
                                locale = lang_item.get('locale', '')
                                if locale == 'zh-Hans':
                                    zh_data = lang_item.get('data', {})
                                elif locale == 'en':
                                    en_data = lang_item.get('data', {})

                            # 优先级：中文优先，没有就用英文，再没有就取第一个
                            target_data = zh_data or en_data or raw_rule['data'][0].get('data', {})

                            parsed_rule['label'] = target_data.get('label', '')
                            # 注意：LibChecker字段名叫 dev_team
                            parsed_rule['team'] = target_data.get('dev_team', '')
                            parsed_rule['description'] = target_data.get('description', '')

                        self.rules.append(parsed_rule)
                        count += 1
                except Exception as e:
                    print(f"[错误] 解析规则文件失败 {filename}: {e}")

        print(f"[成功] 加载了 {count} 条 LibChecker 原生库规则。")

    def match(self, so_path):
        """用规则匹配 SO 文件名"""
        if not self.rules:
            return None

        basename = os.path.basename(so_path)  # 例如从 lib/arm64-v8a/libImSDK.so 拿到 libImSDK.so

        for rule in self.rules:
            is_regex = rule['isRegex']
            rule_name = rule['name'] or rule['_filename']

            if is_regex:
                try:
                    if re.search(rule_name, basename):
                        return rule
                except re.error:
                    pass
            else:
                if basename == rule_name or basename == rule['_filename']:
                    return rule
        return None


# 全局初始化匹配器
MATCHER = LibCheckerMatcher(LIBCHECKER_RULES_DIR)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """避免单个慢连接阻塞全站，并限制并发连接造成的线程耗尽。"""

    daemon_threads = True
    allow_reuse_address = os.name != 'nt'
    request_queue_size = min(MAX_ACTIVE_CONNECTIONS, 128)

    def __init__(self, server_address, handler_class):
        self._connection_slots = threading.BoundedSemaphore(MAX_ACTIVE_CONNECTIONS)
        super().__init__(server_address, handler_class)

    def server_bind(self):
        # Windows 的 SO_REUSEADDR 允许多个进程争抢同一端口；独占绑定可避免假存活。
        if os.name == 'nt' and hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b'HTTP/1.1 503 Service Unavailable\r\n'
                    b'Connection: close\r\nRetry-After: 5\r\nContent-Length: 0\r\n\r\n'
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class RequestHandler(BaseHTTPRequestHandler):
    server_version = 'ObfuScan'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(REQUEST_IDLE_TIMEOUT_SECONDS)

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.send_header('Connection', 'close')
        super().end_headers()

    def send_json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        request_path = self.path.partition('?')[0]
        if request_path == '/':
            body = self.get_index_html().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif request_path == '/status':
            executable, source = resolve_obfuscan_executable()
            payload = {
                'ready': executable is not None,
                'engine': describe_engine(executable, source),
            }
            self.send_json(payload)
        elif request_path == '/favicon.ico':
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.partition('?')[0] != '/analyze':
            self.send_error(404)
            return

        if not SCAN_SLOTS.acquire(blocking=False):
            self.send_json(
                {'error': True, 'message': '服务器当前扫描任务已满，请稍后重试。'},
                429,
                {'Retry-After': '10'},
            )
            return

        try:
            self.handle_analyze()
        except socket.timeout:
            try:
                self.send_json({'error': True, 'message': '上传连接长时间无数据，已终止。'}, 408)
            except OSError:
                pass
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self.log_error('处理分析请求失败: %s', exc)
            try:
                self.send_json({'error': True, 'message': '服务器处理请求失败。'}, 500)
            except OSError:
                pass
        finally:
            SCAN_SLOTS.release()

    def handle_analyze(self):
        content_type = self.headers.get('Content-Type', '')
        content_length = self.headers.get('Content-Length', '')
        if not content_type.lower().startswith('multipart/form-data'):
            self.send_json({'error': True, 'message': '请求必须使用 multipart/form-data。'}, 400)
            return
        if not content_length:
            self.send_json({'error': True, 'message': '请求必须包含 Content-Length。'}, 411)
            return
        try:
            request_bytes = int(content_length)
        except ValueError:
            self.send_json({'error': True, 'message': '无效的 Content-Length。'}, 400)
            return
        if request_bytes <= 0:
            self.send_json({'error': True, 'message': '上传内容为空。'}, 400)
            return
        if request_bytes > MAX_UPLOAD_BYTES:
            self.send_json({'error': True, 'message': 'APK 超过服务端上传大小限制。'}, 413)
            return

        required_free_bytes = request_bytes * 2 + MIN_FREE_DISK_RESERVE_BYTES
        if shutil.disk_usage(tempfile.gettempdir()).free < required_free_bytes:
            self.send_json({'error': True, 'message': '服务器临时磁盘空间不足。'}, 507)
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': content_type,
                'CONTENT_LENGTH': content_length,
            },
        )

        if 'apk' not in form or form['apk'].filename == '':
            self.send_json({'error': True, 'message': '没有收到 APK 文件。'}, 400)
            return

        apk_file = form['apk']
        lang = form.getvalue('lang', 'zh')
        if not str(apk_file.filename).lower().endswith(('.apk', '.hap')):
            self.send_json({'error': True, 'message': '仅支持 .apk / .hap 文件。'}, 400)
            return

        temp_apk_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as temp_file:
                temp_apk_path = temp_file.name
                copied_bytes = 0
                while True:
                    chunk = apk_file.file.read(UPLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    copied_bytes += len(chunk)
                    if copied_bytes > MAX_UPLOAD_BYTES:
                        break
                    temp_file.write(chunk)

            if copied_bytes > MAX_UPLOAD_BYTES:
                self.send_json({'error': True, 'message': 'APK 超过服务端上传大小限制。'}, 413)
                return
            if copied_bytes == 0:
                self.send_json({'error': True, 'message': 'APK 文件为空。'}, 400)
                return
            with open(temp_apk_path, 'rb') as apk_stream:
                zip_magic = apk_stream.read(4)
            if zip_magic not in {b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'}:
                self.send_json({'error': True, 'message': '文件不是有效的 APK/ZIP 容器。'}, 400)
                return

            result = self.run_obfuscan(temp_apk_path, lang)
            self.send_json(result)
        finally:
            if temp_apk_path and os.path.exists(temp_apk_path):
                os.unlink(temp_apk_path)

    def run_obfuscan(self, apk_path, lang='zh'):
        executable, engine_source = resolve_obfuscan_executable()
        engine = describe_engine(executable, engine_source)
        try:
            if executable is None:
                return {
                    'error': True,
                    'message': '未找到当前平台可执行的 ObfuScan。请先完成 Release 构建，或设置 OBFUSCAN_EXECUTABLE。',
                    'engine': engine,
                }

            cmd = [executable, apk_path]
            if lang == 'en':
                cmd.append('--en')

            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                result = subprocess.run(
                    cmd,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=SCAN_TIMEOUT_SECONDS,
                )

                stdout_size = stdout_file.tell()
                stderr_size = stderr_file.tell()
                stderr_file.seek(max(0, stderr_size - MAX_SCANNER_STDERR_BYTES))
                stderr_text = stderr_file.read(MAX_SCANNER_STDERR_BYTES).decode('utf-8', errors='replace')

                if stdout_size > MAX_SCANNER_STDOUT_BYTES:
                    self.log_error('ObfuScan 输出超过限制: %s bytes', stdout_size)
                    return {
                        'error': True,
                        'message': '扫描结果过大，服务器已拒绝加载。',
                        'engine': engine,
                    }

                stdout_file.seek(0)
                stdout_text = stdout_file.read(MAX_SCANNER_STDOUT_BYTES).decode('utf-8', errors='strict')

            if result.returncode != 0:
                self.log_error('ObfuScan 返回非零状态 %s: %s', result.returncode, stderr_text[-4096:])
                message = 'ObfuScan执行失败，请查看服务端日志。'
                if EXPOSE_ENGINE_PATH:
                    message = f'ObfuScan执行失败: {stderr_text[-4096:]}'
                return {'error': True, 'message': message, 'engine': engine}

            try:
                analysis_result = json.loads(stdout_text)

                if lang == 'zh':
                    if '结果' in analysis_result:
                        for item in analysis_result['结果']:
                            so_path = item.get('so文件', '')
                            if so_path:
                                match_rule = MATCHER.match(so_path)
                                if match_rule:
                                    item['LibChecker'] = {
                                        '名称': match_rule['label'] or match_rule['_filename'],
                                        '团队': match_rule['team'],
                                        '描述': match_rule['description']
                                    }
                else:
                    if 'results' in analysis_result:
                        for item in analysis_result['results']:
                            so_path = item.get('so_file', '')
                            if so_path:
                                match_rule = MATCHER.match(so_path)
                                if match_rule:
                                    item['libchecker'] = {
                                        'name': match_rule['label'] or match_rule['_filename'],
                                        'team': match_rule['team'],
                                        'description': match_rule['description']
                                    }

                return {'error': False, 'result': analysis_result, 'engine': engine}
            except json.JSONDecodeError as e:
                return {'error': True, 'message': f'解析JSON出错: {str(e)}', 'engine': engine}
        except subprocess.TimeoutExpired:
            return {
                'error': True,
                'message': f'扫描超过 {SCAN_TIMEOUT_SECONDS} 秒，已终止。',
                'engine': engine,
            }
        except Exception as e:
            self.log_error('运行 ObfuScan 失败: %s', e)
            message = f'发生异常: {str(e)}' if EXPOSE_ENGINE_PATH else '扫描服务发生内部错误。'
            return {'error': True, 'message': message, 'engine': engine}

    def get_index_html(self):
        return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ObfuScan - APK分析工具</title>
    <style>
        :root {
            color-scheme: dark;
            --bg: #060b14;
            --panel: rgba(13, 23, 38, 0.82);
            --panel-solid: #0d1726;
            --panel-strong: #111e31;
            --line: rgba(142, 167, 200, 0.16);
            --line-bright: rgba(116, 247, 220, 0.28);
            --text: #edf5ff;
            --muted: #8fa2bc;
            --cyan: #58e6ff;
            --mint: #65f6bd;
            --violet: #9f8cff;
            --red: #ff5f7e;
            --amber: #ffca66;
            --green: #56e39f;
            --shadow: 0 26px 70px rgba(0, 0, 0, 0.34);
            --radius-xl: 24px;
            --radius-lg: 18px;
            --radius-md: 13px;
        }

        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            margin: 0;
            min-height: 100vh;
            color: var(--text);
            background:
                radial-gradient(circle at 14% -8%, rgba(88, 230, 255, 0.16), transparent 31rem),
                radial-gradient(circle at 90% 5%, rgba(159, 140, 255, 0.13), transparent 30rem),
                var(--bg);
            font-family: Inter, "Segoe UI", "Microsoft YaHei UI", system-ui, -apple-system, sans-serif;
            line-height: 1.65;
        }
        body::before {
            content: "";
            position: fixed;
            inset: 0;
            z-index: -1;
            opacity: 0.24;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(115, 143, 177, 0.08) 1px, transparent 1px),
                linear-gradient(90deg, rgba(115, 143, 177, 0.08) 1px, transparent 1px);
            background-size: 42px 42px;
            mask-image: linear-gradient(to bottom, black, transparent 80%);
        }
        button, input { font: inherit; }
        button { color: inherit; }
        button:focus-visible, input:focus-visible, summary:focus-visible, .upload-zone:focus-visible {
            outline: 2px solid var(--cyan);
            outline-offset: 3px;
        }

        .container { width: min(1440px, calc(100% - 40px)); margin: 0 auto; padding: 26px 0 72px; }
        .hero {
            position: relative;
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 34px;
            align-items: center;
            min-height: 210px;
            padding: 38px 42px;
            overflow: hidden;
            border: 1px solid var(--line);
            border-radius: var(--radius-xl);
            background: linear-gradient(125deg, rgba(16, 31, 50, 0.96), rgba(9, 18, 32, 0.88));
            box-shadow: var(--shadow), inset 0 1px rgba(255, 255, 255, 0.04);
        }
        .hero::before {
            content: "";
            position: absolute;
            width: 360px;
            height: 360px;
            right: -110px;
            top: -175px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(88, 230, 255, 0.28), transparent 68%);
        }
        .hero-copy { position: relative; z-index: 1; }
        .brand-line { display: flex; align-items: center; gap: 13px; margin-bottom: 18px; }
        .brand-mark {
            display: grid;
            place-items: center;
            width: 43px;
            height: 43px;
            border: 1px solid rgba(101, 246, 189, 0.36);
            border-radius: 13px;
            color: var(--mint);
            background: linear-gradient(145deg, rgba(101, 246, 189, 0.13), rgba(88, 230, 255, 0.06));
            box-shadow: 0 0 34px rgba(101, 246, 189, 0.13);
        }
        .brand-mark svg { width: 24px; height: 24px; }
        .brand-kicker { color: var(--mint); font-size: 12px; font-weight: 750; letter-spacing: 0.18em; text-transform: uppercase; }
        h1 { margin: 0; font-size: clamp(31px, 4vw, 52px); line-height: 1.08; letter-spacing: -0.04em; }
        h1 .accent { color: transparent; background: linear-gradient(90deg, var(--cyan), var(--mint)); background-clip: text; }
        .hero p { max-width: 760px; margin: 16px 0 0; color: #a9bad0; font-size: clamp(15px, 1.6vw, 18px); }
        .hero-meta { display: flex; flex-direction: column; align-items: flex-end; gap: 14px; position: relative; z-index: 1; min-width: 245px; }
        .engine-card { width: min(360px, 100%); padding: 11px 13px; border: 1px solid rgba(101, 246, 189, 0.16); border-radius: 13px; background: rgba(3, 9, 18, 0.42); }
        .engine-status {
            display: inline-flex;
            align-items: center;
            gap: 9px;
            padding: 0;
            color: #baf8df;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.04em;
        }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--mint); box-shadow: 0 0 13px var(--mint); }
        .engine-card.offline { border-color: rgba(255, 95, 126, 0.24); }
        .engine-card.offline .engine-status { color: #ffb4c3; }
        .engine-card.offline .status-dot { background: var(--red); box-shadow: 0 0 13px var(--red); }
        .engine-path { display: block; max-width: 330px; margin-top: 5px; overflow: hidden; color: #71859e; font-family: "Cascadia Code", Consolas, monospace; font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
        .lang-switch { display: flex; gap: 4px; padding: 4px; border: 1px solid var(--line); border-radius: 12px; background: rgba(3, 9, 18, 0.54); }
        .lang-btn { padding: 8px 13px; border: 0; border-radius: 8px; color: var(--muted); background: transparent; cursor: pointer; font-size: 13px; font-weight: 650; transition: 160ms ease; }
        .lang-btn:hover { color: var(--text); background: rgba(255, 255, 255, 0.05); }
        .lang-btn.active { color: #06131c; background: linear-gradient(135deg, var(--cyan), var(--mint)); box-shadow: 0 7px 22px rgba(88, 230, 255, 0.18); }
        .lang-btn:disabled { cursor: wait; opacity: 0.55; }

        main { margin-top: 22px; }
        .panel {
            border: 1px solid var(--line);
            border-radius: var(--radius-xl);
            background: var(--panel);
            box-shadow: var(--shadow), inset 0 1px rgba(255, 255, 255, 0.035);
            backdrop-filter: blur(18px);
        }
        .upload-section { padding: 30px; }
        .section-heading { display: flex; justify-content: space-between; align-items: flex-end; gap: 20px; margin-bottom: 23px; }
        .section-eyebrow { margin-bottom: 5px; color: var(--cyan); font-size: 11px; font-weight: 800; letter-spacing: 0.19em; text-transform: uppercase; }
        h2 { margin: 0; font-size: clamp(23px, 2.5vw, 31px); letter-spacing: -0.025em; }
        .section-note { max-width: 520px; color: var(--muted); font-size: 13px; text-align: right; }

        .upload-form { display: grid; grid-template-columns: minmax(0, 1fr) 230px; gap: 16px; }
        .upload-zone {
            position: relative;
            display: flex;
            align-items: center;
            min-height: 142px;
            padding: 23px;
            border: 1px dashed rgba(88, 230, 255, 0.36);
            border-radius: var(--radius-lg);
            background: linear-gradient(135deg, rgba(88, 230, 255, 0.055), rgba(159, 140, 255, 0.035));
            cursor: pointer;
            transition: border-color 180ms ease, transform 180ms ease, background 180ms ease;
        }
        .upload-zone:hover, .upload-zone.dragging {
            border-color: var(--mint);
            background: linear-gradient(135deg, rgba(88, 230, 255, 0.1), rgba(101, 246, 189, 0.065));
            transform: translateY(-2px);
        }
        .upload-zone input { position: absolute; width: 1px; height: 1px; opacity: 0; pointer-events: none; }
        .upload-icon {
            flex: 0 0 auto;
            display: grid;
            place-items: center;
            width: 62px;
            height: 62px;
            margin-right: 19px;
            border: 1px solid rgba(88, 230, 255, 0.24);
            border-radius: 18px;
            color: var(--cyan);
            background: rgba(88, 230, 255, 0.08);
        }
        .upload-icon svg { width: 29px; height: 29px; }
        .upload-copy { min-width: 0; }
        .upload-title { display: block; margin-bottom: 4px; font-size: 17px; font-weight: 750; }
        .upload-hint { color: var(--muted); font-size: 13px; }
        .file-meta { display: none; margin-top: 10px; color: var(--mint); font-size: 13px; overflow-wrap: anywhere; }
        .file-meta.visible { display: block; }
        .form-actions { display: flex; flex-direction: column; gap: 11px; }
        .analyze-btn {
            position: relative;
            flex: 1;
            min-height: 78px;
            padding: 16px 20px;
            overflow: hidden;
            border: 0;
            border-radius: var(--radius-lg);
            color: #06151d;
            background: linear-gradient(135deg, var(--cyan), var(--mint));
            box-shadow: 0 16px 36px rgba(88, 230, 255, 0.18);
            cursor: pointer;
            font-weight: 800;
            transition: transform 180ms ease, box-shadow 180ms ease, opacity 180ms ease;
        }
        .analyze-btn::after { content: "→"; margin-left: 10px; font-size: 20px; }
        .analyze-btn:hover { transform: translateY(-2px); box-shadow: 0 20px 42px rgba(88, 230, 255, 0.26); }
        .analyze-btn:disabled { cursor: wait; opacity: 0.55; transform: none; }
        .privacy-note { display: flex; align-items: center; justify-content: center; gap: 7px; color: var(--muted); font-size: 11px; }
        .privacy-note svg { width: 13px; height: 13px; color: var(--mint); }

        .loading { display: none; position: relative; margin-top: 17px; padding: 20px 22px; overflow: hidden; border: 1px solid rgba(88, 230, 255, 0.18); border-radius: var(--radius-lg); background: rgba(6, 14, 26, 0.72); }
        .loading.active { display: flex; align-items: center; gap: 17px; }
        .scanner {
            position: relative;
            flex: 0 0 auto;
            width: 42px;
            height: 42px;
            border: 2px solid rgba(88, 230, 255, 0.14);
            border-top-color: var(--cyan);
            border-right-color: var(--mint);
            border-radius: 50%;
            animation: spin 950ms linear infinite;
        }
        .scanner::after { content: ""; position: absolute; inset: 9px; border-radius: 50%; background: radial-gradient(circle, var(--cyan), transparent 67%); }
        .loading-copy strong { display: block; font-size: 14px; }
        .loading-copy span { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
        .scan-line { position: absolute; left: 0; bottom: 0; width: 35%; height: 2px; background: linear-gradient(90deg, transparent, var(--cyan), var(--mint), transparent); animation: scan 1.8s ease-in-out infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes scan { 0%, 100% { transform: translateX(-100%); } 50% { transform: translateX(285%); } }

        .results-section { display: none; margin-top: 22px; }
        .results-section.visible { display: block; }
        .results-head { padding: 27px 30px 0; }
        .summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 13px; padding: 22px 30px 30px; }
        .summary-card {
            position: relative;
            min-height: 116px;
            padding: 18px;
            overflow: hidden;
            border: 1px solid var(--line);
            border-radius: var(--radius-lg);
            background: linear-gradient(145deg, rgba(255, 255, 255, 0.035), rgba(255, 255, 255, 0.012));
        }
        .summary-card::after { content: ""; position: absolute; width: 90px; height: 90px; right: -34px; top: -35px; border-radius: 50%; background: var(--card-color); opacity: 0.09; filter: blur(2px); }
        .summary-card.total { --card-color: var(--cyan); }
        .summary-card.high { --card-color: var(--red); }
        .summary-card.medium { --card-color: var(--amber); }
        .summary-card.low { --card-color: var(--green); }
        .summary-card.likely { --card-color: var(--red); }
        .summary-card.client { --card-color: var(--violet); }
        .summary-card.suspicious { --card-color: var(--amber); }
        .summary-card.runtime { --card-color: var(--green); }
        .summary-label { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; font-weight: 650; }
        .summary-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--card-color); box-shadow: 0 0 12px var(--card-color); }
        .summary-value { margin-top: 8px; color: var(--card-color); font-family: "Cascadia Code", Consolas, monospace; font-size: 31px; font-weight: 780; line-height: 1; }
        .summary > .error-message { grid-column: 1 / -1; }
        .scan-status-banner { grid-column: 1 / -1; padding: 14px 16px; border: 1px solid rgba(101, 246, 189, 0.22); border-radius: var(--radius-md); color: #c9fbe7; background: rgba(86, 227, 159, 0.07); }
        .scan-status-banner.partial { border-color: rgba(255, 202, 102, 0.28); color: #ffe1a5; background: rgba(255, 202, 102, 0.08); }
        .scan-status-banner.rejected, .scan-status-banner.error { border-color: rgba(255, 95, 126, 0.3); color: #ffbdca; background: rgba(255, 95, 126, 0.09); }
        .scan-status-title { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px 16px; font-weight: 800; }
        .scan-status-meta { color: var(--muted); font-size: 12px; font-weight: 650; }
        .scan-diagnostics { margin: 10px 0 0; padding-left: 18px; color: inherit; font-size: 12px; }
        .scan-diagnostics li + li { margin-top: 5px; }
        #resultList { display: grid; gap: 14px; margin-top: 15px; }

        .result-item {
            --risk: var(--green);
            position: relative;
            overflow: hidden;
            border: 1px solid var(--line);
            border-radius: var(--radius-lg);
            background: rgba(10, 19, 32, 0.88);
            box-shadow: 0 15px 45px rgba(0, 0, 0, 0.2);
        }
        .result-item::before { content: ""; position: absolute; z-index: 1; left: 0; top: 0; bottom: 0; width: 3px; background: var(--risk); box-shadow: 0 0 18px var(--risk); }
        .result-item.high { --risk: var(--red); }
        .result-item.medium { --risk: var(--amber); }
        .result-item.low { --risk: var(--green); }
        .result-item > details > summary { list-style: none; }
        .result-item > details > summary::-webkit-details-marker { display: none; }
        .result-header { display: flex; justify-content: space-between; align-items: center; gap: 18px; padding: 20px 23px; cursor: pointer; user-select: none; }
        .result-header:hover { background: rgba(255, 255, 255, 0.02); }
        .so-identity { display: flex; align-items: center; min-width: 0; gap: 13px; }
        .so-icon { display: grid; flex: 0 0 auto; place-items: center; width: 38px; height: 38px; border: 1px solid color-mix(in srgb, var(--risk) 28%, transparent); border-radius: 11px; color: var(--risk); background: color-mix(in srgb, var(--risk) 8%, transparent); font-family: Consolas, monospace; font-size: 12px; font-weight: 800; }
        .so-name { display: block; overflow: hidden; color: var(--text); font-family: "Cascadia Code", Consolas, monospace; font-size: 14px; font-weight: 690; text-overflow: ellipsis; white-space: nowrap; }
        .so-caption { display: block; margin-top: 2px; color: var(--muted); font-size: 11px; }
        .header-actions { display: flex; align-items: center; gap: 12px; }
        .risk-level { padding: 5px 10px; border: 1px solid color-mix(in srgb, var(--risk) 30%, transparent); border-radius: 999px; color: var(--risk); background: color-mix(in srgb, var(--risk) 8%, transparent); font-size: 11px; font-weight: 800; letter-spacing: 0.08em; }
        .chevron { width: 8px; height: 8px; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: rotate(45deg); transition: transform 180ms ease; }
        details[open] > summary .chevron { transform: rotate(225deg); }
        .result-details { padding: 0 23px 23px; border-top: 1px solid var(--line); }
        .overview-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 18px; }
        .detail-item { padding: 12px 14px; border: 1px solid rgba(142, 167, 200, 0.1); border-radius: var(--radius-md); color: #c7d4e5; background: rgba(255, 255, 255, 0.018); overflow-wrap: anywhere; }
        .detail-label { color: var(--muted); font-size: 11px; font-weight: 750; letter-spacing: 0.035em; text-transform: uppercase; }
        .suspicious-points, .entry-previews { margin-top: 14px; padding: 15px; border: 1px solid rgba(255, 202, 102, 0.14); border-radius: var(--radius-md); background: rgba(255, 202, 102, 0.035); }
        .suspicious-points ul, .vmp-details ul { margin: 9px 0 0 20px; padding: 0; color: #c7d4e5; }
        .suspicious-points li::marker, .vmp-details li::marker { color: var(--amber); }
        .entry-preview { margin-top: 9px; padding: 11px 13px; border: 1px solid var(--line); border-radius: 10px; color: #b7c7da; background: rgba(4, 10, 18, 0.48); overflow-wrap: anywhere; }

        .libchecker-info { margin-top: 18px; padding: 14px 16px; border: 1px solid rgba(86, 227, 159, 0.2); border-radius: var(--radius-md); background: linear-gradient(135deg, rgba(86, 227, 159, 0.08), rgba(88, 230, 255, 0.025)); }
        .libchecker-name { color: #9ff2c7; font-size: 15px; }
        .libchecker-team { margin-left: 7px; color: var(--muted); font-size: 12px; }
        .libchecker-desc { margin-top: 7px; color: #9eb0c6; font-size: 12px; }

        .custom-linker-info { --linker-tone: var(--amber); position: relative; margin-top: 16px; padding: 18px; overflow: hidden; border: 1px solid rgba(255, 202, 102, 0.24); border-radius: var(--radius-lg); background: linear-gradient(135deg, rgba(255, 202, 102, 0.085), rgba(88, 230, 255, 0.025)); }
        .custom-linker-info.outcome-protection { --linker-tone: var(--red); border-color: rgba(255, 95, 126, 0.28); background: linear-gradient(135deg, rgba(255, 95, 126, 0.105), rgba(255, 202, 102, 0.025)); }
        .custom-linker-info::after { content: "ELF"; position: absolute; right: -8px; top: -19px; color: color-mix(in srgb, var(--linker-tone) 7%, transparent); font-family: Consolas, monospace; font-size: 78px; font-weight: 900; line-height: 1; pointer-events: none; }
        .custom-linker-headline { position: relative; z-index: 1; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 12px; color: #e4edf8; font-size: 15px; font-weight: 700; }
        .custom-linker-outcome-code { display: inline-block; padding: 4px 9px; border: 1px solid color-mix(in srgb, var(--linker-tone) 34%, transparent); border-radius: 999px; color: var(--linker-tone); background: color-mix(in srgb, var(--linker-tone) 9%, transparent); font-family: "Cascadia Code", Consolas, monospace; font-size: 10px; font-weight: 750; }
        .custom-linker-metrics, .custom-linker-evidence-grid { position: relative; z-index: 1; display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 8px; }
        .custom-linker-metric, .custom-linker-evidence-item { min-width: 0; padding: 10px 12px; border: 1px solid rgba(142, 167, 200, 0.11); border-radius: 10px; color: #d7e3f2; background: rgba(4, 10, 19, 0.35); overflow-wrap: anywhere; }
        .custom-linker-metric .detail-label, .custom-linker-evidence-item .detail-label { display: block; margin-bottom: 3px; }
        .custom-linker-evidence { position: relative; z-index: 1; margin-top: 10px; border: 1px solid rgba(142, 167, 200, 0.12); border-radius: 11px; background: rgba(5, 11, 21, 0.38); }
        .custom-linker-evidence > summary { padding: 11px 13px; color: var(--linker-tone); cursor: pointer; font-size: 12px; font-weight: 750; }
        .custom-linker-evidence[open] > summary { border-bottom: 1px solid var(--line); }
        .custom-linker-evidence-grid { padding: 10px; }

        .vmp-info { --vmp-tone: var(--violet); position: relative; margin-top: 16px; padding: 20px; overflow: hidden; border: 1px solid rgba(159, 140, 255, 0.22); border-radius: var(--radius-lg); background: linear-gradient(135deg, rgba(159, 140, 255, 0.09), rgba(88, 230, 255, 0.035)); }
        .vmp-info.outcome-likely { --vmp-tone: var(--red); border-color: rgba(255, 95, 126, 0.28); background: linear-gradient(135deg, rgba(255, 95, 126, 0.11), rgba(159, 140, 255, 0.035)); }
        .vmp-info.outcome-client { --vmp-tone: var(--violet); border-color: rgba(159, 140, 255, 0.3); background: linear-gradient(135deg, rgba(159, 140, 255, 0.12), rgba(88, 230, 255, 0.045)); }
        .vmp-info.outcome-suspicious { --vmp-tone: var(--amber); border-color: rgba(255, 202, 102, 0.26); background: linear-gradient(135deg, rgba(255, 202, 102, 0.09), rgba(159, 140, 255, 0.025)); }
        .vmp-info.outcome-runtime { --vmp-tone: var(--green); border-color: rgba(86, 227, 159, 0.24); background: linear-gradient(135deg, rgba(86, 227, 159, 0.085), rgba(88, 230, 255, 0.03)); }
        .vmp-info.outcome-unknown { --vmp-tone: #a8b7cb; border-color: rgba(168, 183, 203, 0.2); background: linear-gradient(135deg, rgba(168, 183, 203, 0.06), rgba(159, 140, 255, 0.02)); }
        .vmp-info::after { content: "VM"; position: absolute; right: -8px; top: -26px; color: color-mix(in srgb, var(--vmp-tone) 7%, transparent); font-family: Consolas, monospace; font-size: 106px; font-weight: 900; line-height: 1; pointer-events: none; }
        .vmp-headline { position: relative; z-index: 1; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 15px; font-size: 16px; font-weight: 700; }
        .vmp-outcome-code { display: inline-block; padding: 4px 9px; border: 1px solid color-mix(in srgb, var(--vmp-tone) 34%, transparent); border-radius: 999px; color: var(--vmp-tone); background: color-mix(in srgb, var(--vmp-tone) 9%, transparent); font-family: "Cascadia Code", Consolas, monospace; font-size: 10px; font-weight: 750; }
        .vmp-axis-grid, .vmp-metric-grid { position: relative; z-index: 1; display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 8px; margin: 10px 0; }
        .vmp-axis, .vmp-metric { min-width: 0; padding: 10px 12px; border: 1px solid rgba(142, 167, 200, 0.11); border-radius: 10px; color: #d7e3f2; background: rgba(4, 10, 19, 0.35); overflow-wrap: anywhere; }
        .vmp-axis .detail-label, .vmp-metric .detail-label { display: block; margin-bottom: 3px; }
        .vmp-score-note { position: relative; z-index: 1; margin: 12px 0; padding: 10px 12px; border: 1px solid rgba(255, 202, 102, 0.13); border-radius: 10px; color: #c7b987; background: rgba(255, 202, 102, 0.045); font-size: 11px; }
        .vmp-details { position: relative; z-index: 1; margin-top: 10px; border: 1px solid var(--line); border-radius: 11px; background: rgba(5, 11, 21, 0.38); }
        .vmp-details:not(details) { padding: 12px 14px; }
        .vmp-details > summary { padding: 11px 13px; color: #bfb3ff; cursor: pointer; font-size: 12px; font-weight: 750; }
        .vmp-details[open] > summary { border-bottom: 1px solid var(--line); }
        .vmp-details > .vmp-metric-grid { padding: 0 11px 11px; }
        .vmp-candidate { margin: 9px 11px; padding: 12px; border: 1px solid rgba(88, 230, 255, 0.12); border-radius: 10px; color: #b9c9dc; background: rgba(88, 230, 255, 0.025); overflow-wrap: anywhere; }
        .vmp-candidate strong { color: var(--cyan); font-family: Consolas, monospace; }
        .vmp-registers { margin-top: 6px; color: #92a8bf; font-family: "Cascadia Code", Consolas, monospace; font-size: 11px; }
        .vmp-limitation, .vmp-alternative { position: relative; z-index: 1; margin-top: 10px; padding: 11px 13px; border-radius: 10px; font-size: 12px; }
        .vmp-limitation { border: 1px solid rgba(255, 202, 102, 0.18); color: #d1bc88; background: rgba(255, 202, 102, 0.05); }
        .vmp-alternative { border: 1px solid rgba(86, 227, 159, 0.18); color: #a3dcbf; background: rgba(86, 227, 159, 0.05); }
        .runtime-evidence { position: relative; z-index: 1; margin: 12px 0; padding: 14px; border: 1px solid rgba(255, 202, 102, 0.16); border-radius: 12px; background: rgba(255, 202, 102, 0.045); }
        .provider-evidence { position: relative; z-index: 1; margin: 12px 0; padding: 14px; border: 1px solid rgba(159, 140, 255, 0.24); border-radius: 12px; background: linear-gradient(135deg, rgba(159, 140, 255, 0.11), rgba(88, 230, 255, 0.035)); }
        .provider-symbols { margin-top: 8px; color: #d1c9ff; font-family: "Cascadia Code", Consolas, monospace; font-size: 11px; overflow-wrap: anywhere; }
        .runtime-evidence.confirmed { border-color: rgba(86, 227, 159, 0.2); background: rgba(86, 227, 159, 0.05); }
        .runtime-evidence-status { margin-top: 8px; color: #d7e3f2; font-size: 12px; font-weight: 700; }
        .runtime-evidence-rule { margin-top: 5px; color: var(--muted); font-size: 11px; }
        .suggestion { margin-top: 14px; border-color: rgba(88, 230, 255, 0.14); background: rgba(88, 230, 255, 0.035); }
        .error-message { padding: 15px 17px; border: 1px solid rgba(255, 95, 126, 0.26); border-radius: var(--radius-md); color: #ffb4c3; background: rgba(255, 95, 126, 0.08); overflow-wrap: anywhere; }
        .empty-state { padding: 35px; color: var(--muted); text-align: center; }

        @media (max-width: 820px) {
            .container { width: min(100% - 24px, 1440px); padding-top: 12px; }
            .hero { grid-template-columns: 1fr; min-height: auto; padding: 28px 24px; }
            .hero-meta { flex-direction: row; align-items: center; justify-content: space-between; }
            .upload-section { padding: 22px; }
            .upload-form { grid-template-columns: 1fr; }
            .form-actions { flex-direction: row; align-items: center; }
            .analyze-btn { min-height: 60px; }
            .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 18px 20px 22px; }
            .results-head { padding: 23px 20px 0; }
            .overview-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 540px) {
            .section-heading { align-items: flex-start; flex-direction: column; }
            .section-note { text-align: left; }
            .upload-zone { align-items: flex-start; min-height: 158px; padding: 20px; }
            .upload-icon { width: 48px; height: 48px; margin-right: 13px; border-radius: 14px; }
            .hero-meta, .form-actions { align-items: stretch; flex-direction: column; }
            .summary { gap: 9px; }
            .summary-card { min-height: 100px; padding: 15px; }
            .result-header { align-items: flex-start; padding: 17px; }
            .result-details { padding: 0 17px 17px; }
            .so-name { max-width: 48vw; }
            .so-caption { display: none; }
            .vmp-info { padding: 15px; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; transition-duration: 0.01ms !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="hero">
            <div class="hero-copy">
                <div class="brand-line">
                    <span class="brand-mark" aria-hidden="true">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 2.8 20 6v5.3c0 4.8-3.3 8.4-8 9.9-4.7-1.5-8-5.1-8-9.9V6l8-3.2Z"/><path d="M8.3 12.1 10.8 14.6 16.2 9.2"/></svg>
                    </span>
                    <span class="brand-kicker">Native Security Intelligence</span>
                </div>
                <h1 id="title">Obfu<span class="accent">Scan</span></h1>
                <p id="subtitle">面向 Android Native 的深度静态分析，识别混淆、加壳、VMP 与异常装载链路。</p>
            </div>
            <div class="hero-meta">
                <div class="engine-card" id="engineCard">
                    <div class="engine-status"><span class="status-dot"></span><span id="engineStatus">正在确认扫描引擎</span></div>
                    <code class="engine-path" id="enginePath">checking...</code>
                </div>
                <div class="lang-switch" role="group" aria-label="Language">
                    <button type="button" id="langZh" class="lang-btn active" onclick="switchLang('zh')">中文</button>
                    <button type="button" id="langEn" class="lang-btn" onclick="switchLang('en')">English</button>
                </div>
            </div>
        </header>

        <main>
            <section class="upload-section panel" aria-labelledby="uploadTitle">
                <div class="section-heading">
                    <div>
                        <div class="section-eyebrow" id="uploadEyebrow">SCAN CONSOLE · 本地分析</div>
                        <h2 id="uploadTitle">提交分析目标</h2>
                    </div>
                    <p class="section-note" id="uploadNote">提取 APK / HAP 内的 Native SO，并对控制流、VM 调度器、保护意图与合法运行时证据进行交叉判定。</p>
                </div>
                <form class="upload-form" id="uploadForm" enctype="multipart/form-data">
                    <label class="upload-zone" id="uploadZone" for="apkFile" tabindex="0">
                        <input type="file" id="apkFile" name="apk" accept=".apk,.hap,application/vnd.android.package-archive">
                        <span class="upload-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"/><path d="M5 14.5v3A2.5 2.5 0 0 0 7.5 20h9a2.5 2.5 0 0 0 2.5-2.5v-3"/></svg>
                        </span>
                        <span class="upload-copy">
                            <span class="upload-title" id="selectFileLabel">拖放 APK / HAP 到这里，或点击选择</span>
                            <span class="upload-hint" id="uploadHint">支持中文路径 · 文件仅在本机分析</span>
                            <span class="file-meta" id="fileMeta"></span>
                        </span>
                    </label>
                    <div class="form-actions">
                        <button class="analyze-btn" type="submit" id="analyzeBtn">启动深度扫描</button>
                        <span class="privacy-note">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/></svg>
                            <span id="privacyText">127.0.0.1 · 本地处理</span>
                        </span>
                    </div>
                </form>
                <div class="loading" id="loading" role="status" aria-live="polite">
                    <span class="scanner" aria-hidden="true"></span>
                    <span class="loading-copy"><strong id="loadingText">正在解析 Native 结构与组件指纹</strong><span id="loadingFile"></span></span>
                    <span class="scan-line" aria-hidden="true"></span>
                </div>
            </section>

            <section class="results-section" id="resultsSection" aria-labelledby="resultsTitle">
                <div class="panel">
                    <div class="results-head section-heading">
                        <div>
                            <div class="section-eyebrow" id="resultsEyebrow">THREAT LANDSCAPE</div>
                            <h2 id="resultsTitle">扫描结论</h2>
                        </div>
                        <p class="section-note" id="resultsNote">风险等级用于排序；VMP 分数表示静态证据强度，并非概率。</p>
                    </div>
                    <div class="summary" id="summary"></div>
                </div>
                <div id="resultList"></div>
            </section>
        </main>
    </div>
    
    <script>
        const lang = {
            zh: {
                title: 'ObfuScan - APK分析工具',
                subtitle: '面向 Android Native 的深度静态分析，识别混淆、加壳、VMP 与异常装载链路。',
                uploadEyebrow: 'SCAN CONSOLE · 本地分析',
                uploadTitle: '提交分析目标',
                uploadNote: '提取 APK / HAP 内的 Native SO，并对控制流、VM 调度器、保护意图与合法运行时证据进行交叉判定。',
                selectFileLabel: '拖放 APK / HAP 到这里，或点击选择',
                uploadHint: '支持中文路径 · 文件仅在本机分析',
                analyzeBtn: '启动深度扫描',
                loadingText: '正在解析 Native 结构与组件指纹',
                privacyText: '127.0.0.1 · 本地处理',
                engineChecking: '正在确认扫描引擎',
                engineReady: 'AArch64 引擎就绪',
                engineMissing: '扫描引擎不可用',
                resultsEyebrow: 'THREAT LANDSCAPE',
                resultsTitle: '扫描结论',
                resultsNote: '风险等级用于排序；VMP 分数表示静态证据强度，并非概率。',
                summary: '汇总信息',
                totalSo: '总SO数量',
                highRisk: '高风险',
                mediumRisk: '中风险',
                lowRisk: '低风险',
                likelyVmpCount: '高置信VMP',
                protectedClientCount: 'VMP保护客户端',
                suspiciousVmpCount: '仅结构待复核',
                runtimeCount: '合法运行时解释',
                scanStatus: '扫描状态',
                scanAnalyzed: '已分析 SO',
                scanSkipped: '已跳过 SO',
                scanDiagnostics: '安全诊断',
                knownComponent: '💡 已知组件',
                detectionResult: '检测结果',
                description: '说明',
                suspiciousPoints: '可疑点',
                entryPreview: '入口预览',
                name: '名称',
                address: '地址',
                preview: '预览',
                customLinkerJudgment: '自定义Linker判断',
                customLinkerScore: '自定义Linker分数',
                customLinkerOutcome: '状态码',
                customLinkerConfidence: '置信度',
                customLinkerLoaderScore: '装载器分数',
                customLinkerProtectionScore: '加固分数',
                customLinkerEvidence: '结构化证据',
                customLinkerComponentJudgment: '自定义 ELF Loader 组件（未证实加固）',
                customLinkerProtectionJudgment: '疑似自定义 Linker 加固',
                vmpJudgment: 'VMP判断',
                vmpOutcome: '状态码',
                vmpConfidence: '置信度',
                vmpProfile: '类型',
                vmpScore: 'VMP分数',
                vmStructureScore: 'VM结构分数',
                protectionIntentScore: '保护意图分数',
                alternativePenalty: '替代解释扣分',
                vmpCoverage: '扫描覆盖率',
                vmpObservable: '静态可观测',
                vmpMetrics: '扫描指标',
                vmpCandidates: '候选点',
                vmpFeatures: 'VMP特征',
                vmpAlternative: '替代解释',
                vmpLimitation: '分析限制',
                vmpScoreNote: '分数表示当前静态证据强度，不是“属于VMP”的概率。请结合状态码、替代解释与分析限制判断。',
                runtimeEvidence: '运行时替代解释证据',
                runtimeFamily: '运行时类型',
                runtimeEvidenceClasses: '独立证据类别数',
                runtimeConfirmed: '已确认替代解释',
                runtimeRawIdentityHits: '身份字符串命中',
                runtimeImportApiHits: '导入API命中',
                runtimeWeakHint: '弱提示：当前只有 1 类证据，不能单独确认合法运行时替代解释。',
                runtimeConfirmedHint: '已确认：至少 2 类独立证据相互印证，可作为合法运行时替代解释。',
                runtimeEvidenceRule: '判定规则：1 类证据仅作弱提示；至少 2 类独立证据才确认替代解释。重复命中次数不会增加证据类别数。',
                vmpDependencyEvidence: '跨SO依赖证据',
                vmpProvider: 'VMP提供库',
                neededLibrary: 'DT_NEEDED',
                sharedSymbols: '导入/导出交集',
                yes: '是',
                no: '否',
                executableBytes: '可执行字节',
                scannedBytes: '扫描字节',
                decodedCandidateBytes: '候选反汇编字节',
                rawIndirectTransfers: '原始间接转移',
                uniqueCandidates: '去重候选',
                strongCandidates: '强候选',
                mediumCandidates: '中候选',
                dominantVipSites: '共享VPC最大候选数',
                maxClusterSites: '4KB最大聚类数',
                candidateRegion: '区域',
                candidateKind: '类型',
                candidateStrength: '强度',
                candidateTraits: '特征',
                suggestion: '建议',
                selectApk: '请选择APK文件',
                invalidApk: '请选择扩展名为 .apk 或 .hap 的文件',
                fileReady: '已选择',
                soDetails: '点击展开完整证据',
                emptyResults: '扫描完成，但没有返回可展示的 SO 结果。',
                languageChanged: '语言已切换，请重新分析。',
                error: '异常',
                high: '高',
                medium: '中',
                low: '低'
            },
            en: {
                title: 'ObfuScan - APK Analyzer',
                subtitle: 'Deep static analysis for Android Native code, covering obfuscation, packing, VMP, and abnormal loading chains.',
                uploadEyebrow: 'SCAN CONSOLE · LOCAL ANALYSIS',
                uploadTitle: 'Submit Analysis Target',
                uploadNote: 'Extract Native SO files and correlate control flow, VM dispatchers, protection intent, and legitimate-runtime evidence.',
                selectFileLabel: 'Drop an APK or HAP here, or click to browse',
                uploadHint: 'Unicode paths supported · Processed locally',
                analyzeBtn: 'Launch Deep Scan',
                loadingText: 'Parsing Native structures and component fingerprints',
                privacyText: '127.0.0.1 · Local processing',
                engineChecking: 'Resolving analysis engine',
                engineReady: 'AArch64 engine ready',
                engineMissing: 'Analysis engine unavailable',
                resultsEyebrow: 'THREAT LANDSCAPE',
                resultsTitle: 'Scan Verdicts',
                resultsNote: 'Risk levels prioritize review; VMP scores express static evidence strength, not probability.',
                summary: 'Summary',
                totalSo: 'Total SO Count',
                highRisk: 'High Risk',
                mediumRisk: 'Medium Risk',
                lowRisk: 'Low Risk',
                likelyVmpCount: 'High-confidence VMP',
                protectedClientCount: 'VMP-protected Clients',
                suspiciousVmpCount: 'Structure-only Review',
                runtimeCount: 'Legitimate Runtime',
                scanStatus: 'Scan Status',
                scanAnalyzed: 'Analyzed SOs',
                scanSkipped: 'Skipped SOs',
                scanDiagnostics: 'Safety Diagnostics',
                knownComponent: '💡 Known Component',
                detectionResult: 'Detection Result',
                description: 'Description',
                suspiciousPoints: 'Suspicious Points',
                entryPreview: 'Entry Previews',
                name: 'Name',
                address: 'Address',
                preview: 'Preview',
                customLinkerJudgment: 'Custom Linker Judgment',
                customLinkerScore: 'Custom Linker Score',
                customLinkerOutcome: 'Outcome',
                customLinkerConfidence: 'Confidence',
                customLinkerLoaderScore: 'Loader Score',
                customLinkerProtectionScore: 'Protection Score',
                customLinkerEvidence: 'Structured Evidence',
                customLinkerComponentJudgment: 'Custom ELF Loader component (protection not established)',
                customLinkerProtectionJudgment: 'Likely custom Linker protection',
                vmpJudgment: 'VMP Judgment',
                vmpOutcome: 'Outcome',
                vmpConfidence: 'Confidence',
                vmpProfile: 'Profile',
                vmpScore: 'VMP Score',
                vmStructureScore: 'VM Structure Score',
                protectionIntentScore: 'Protection Intent Score',
                alternativePenalty: 'Alternative Penalty',
                vmpCoverage: 'Scan Coverage',
                vmpObservable: 'Statically Observable',
                vmpMetrics: 'Scan Metrics',
                vmpCandidates: 'Candidate Sites',
                vmpFeatures: 'VMP Features',
                vmpAlternative: 'Alternative Explanation',
                vmpLimitation: 'Analysis Limitation',
                vmpScoreNote: 'Scores express the strength of current static evidence, not the probability that the SO is VMP-protected. Read them with the outcome, alternatives, and limitations.',
                runtimeEvidence: 'Runtime Alternative Evidence',
                runtimeFamily: 'Runtime Family',
                runtimeEvidenceClasses: 'Independent Evidence Classes',
                runtimeConfirmed: 'Confirmed Alternative',
                runtimeRawIdentityHits: 'Raw Identity Hits',
                runtimeImportApiHits: 'Imported API Hits',
                runtimeWeakHint: 'Weak hint: one evidence class alone cannot confirm a legitimate-runtime alternative.',
                runtimeConfirmedHint: 'Confirmed: at least two independent evidence classes corroborate the legitimate-runtime alternative.',
                runtimeEvidenceRule: 'Rule: one evidence class is only a weak hint; at least two independent classes are required for confirmation. Repeated hits do not create additional classes.',
                vmpDependencyEvidence: 'Cross-SO Dependency Evidence',
                vmpProvider: 'VMP Provider',
                neededLibrary: 'DT_NEEDED',
                sharedSymbols: 'Import/Export Intersection',
                yes: 'Yes',
                no: 'No',
                executableBytes: 'Executable Bytes',
                scannedBytes: 'Scanned Bytes',
                decodedCandidateBytes: 'Candidate Bytes Disassembled',
                rawIndirectTransfers: 'Raw Indirect Transfers',
                uniqueCandidates: 'Deduplicated Candidates',
                strongCandidates: 'Strong Candidates',
                mediumCandidates: 'Medium Candidates',
                dominantVipSites: 'Max Candidates Sharing VPC',
                maxClusterSites: 'Max 4KB Cluster',
                candidateRegion: 'Region',
                candidateKind: 'Kind',
                candidateStrength: 'Strength',
                candidateTraits: 'Traits',
                suggestion: 'Suggestion',
                selectApk: 'Please select an APK file',
                invalidApk: 'Please select a file with the .apk or .hap extension',
                fileReady: 'Selected',
                soDetails: 'Open to inspect complete evidence',
                emptyResults: 'The scan completed without displayable SO results.',
                languageChanged: 'Language changed. Please run analysis again.',
                error: 'Error',
                high: 'High',
                medium: 'Medium',
                low: 'Low'
            }
        };
        
        let currentLang = 'zh';
        let lastResult = null;
        let selectedFile = null;
        let engineState = { loaded: false, ready: false, path: '', source: '' };

        function firstValue() {
            for (let i = 0; i < arguments.length; i++) {
                if (arguments[i] !== undefined && arguments[i] !== null) return arguments[i];
            }
            return '';
        }

        function firstMeaningfulValue() {
            for (let i = 0; i < arguments.length; i++) {
                const value = arguments[i];
                if (value === undefined || value === null) continue;
                if (typeof value === 'string' && value.trim() === '') continue;
                return value;
            }
            return '';
        }

        function escapeHtml(value) {
            const text = String(value === undefined || value === null ? '' : value);
            return text.replace(/[&<>"']/g, character => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            })[character]);
        }

        function displayValue(value) {
            return value === undefined || value === null || value === '' ? '—' : escapeHtml(value);
        }

        function formatScore(value) {
            if (value === undefined || value === null || value === '') return '—';
            const number = Number(value);
            return Number.isFinite(number) ? number.toFixed(4) : value;
        }

        function formatCoverage(value) {
            if (value === undefined || value === null || value === '') return '—';
            const number = Number(value);
            return Number.isFinite(number) ? (number * 100).toFixed(1) + '%' : value;
        }

        function formatFileSize(bytes) {
            if (!Number.isFinite(bytes) || bytes < 0) return '—';
            const units = ['B', 'KB', 'MB', 'GB'];
            let value = bytes;
            let unit = 0;
            while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
            return value.toFixed(unit === 0 ? 0 : 1) + ' ' + units[unit];
        }

        function classifyVmpOutcome(outcome) {
            const code = String(outcome === undefined || outcome === null ? '' : outcome).trim().toUpperCase();
            const classes = {
                'LIKELY_VMP': 'outcome-likely',
                'VMP_PROTECTED_CLIENT': 'outcome-client',
                'SUSPICIOUS_VM_STRUCTURE': 'outcome-suspicious',
                'VM_LIKE_INTERPRETER': 'outcome-runtime'
            };
            return classes[code] || 'outcome-unknown';
        }

        function renderVmpMetric(label, value) {
            return '<div class="vmp-metric"><span class="detail-label">' + escapeHtml(label) + '</span>' + displayValue(value) + '</div>';
        }

        function renderCustomLinkerMetric(label, value, isScore) {
            if (value === undefined || value === null || value === '') return '';
            const shownValue = isScore ? formatScore(value) : value;
            return '<div class="custom-linker-metric"><span class="detail-label">' + escapeHtml(label) + '</span>' + displayValue(shownValue) + '</div>';
        }

        function formatEvidenceValue(value) {
            if (Array.isArray(value)) {
                if (value.length === 0) return '—';
                const visible = value.slice(0, 16).map(entry => {
                    if (entry && typeof entry === 'object') return JSON.stringify(entry);
                    return String(entry);
                });
                if (value.length > visible.length) visible.push('… +' + (value.length - visible.length));
                return visible.join(' · ');
            }
            if (value && typeof value === 'object') return JSON.stringify(value);
            return value;
        }

        function flattenCustomLinkerEvidence(value, prefix, rows, depth) {
            if (rows.length >= 24) return;
            if (value && typeof value === 'object' && !Array.isArray(value) && depth < 2) {
                const entries = Object.entries(value);
                if (entries.length === 0) {
                    if (prefix) rows.push([prefix, '—']);
                    return;
                }
                entries.forEach(entry => {
                    if (rows.length >= 24) return;
                    const key = prefix ? prefix + ' / ' + entry[0] : entry[0];
                    const nested = entry[1];
                    if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
                        flattenCustomLinkerEvidence(nested, key, rows, depth + 1);
                    } else {
                        rows.push([key, formatEvidenceValue(nested)]);
                    }
                });
                return;
            }
            rows.push([prefix || 'evidence', formatEvidenceValue(value)]);
        }

        function renderCustomLinkerEvidence(label, evidence) {
            if (evidence === undefined || evidence === null || evidence === '') return '';
            const rows = [];
            flattenCustomLinkerEvidence(evidence, '', rows, 0);
            if (rows.length === 0) return '';
            let html = '<details class="custom-linker-evidence"><summary>' + escapeHtml(label) + '</summary><div class="custom-linker-evidence-grid">';
            rows.forEach(row => {
                const key = String(row[0]).replace(/_/g, ' ');
                html += '<div class="custom-linker-evidence-item"><span class="detail-label">' + escapeHtml(key) + '</span>' + displayValue(row[1]) + '</div>';
            });
            html += '</div></details>';
            return html;
        }

        function renderEngineState() {
            const t = lang[currentLang];
            const card = document.getElementById('engineCard');
            const status = document.getElementById('engineStatus');
            const path = document.getElementById('enginePath');
            card.classList.toggle('offline', engineState.loaded && !engineState.ready);
            status.textContent = !engineState.loaded ? t.engineChecking : (engineState.ready ? t.engineReady : t.engineMissing);
            const detail = engineState.ready ? engineState.source + ' · ' + engineState.path : 'ObfuScan.exe —';
            path.textContent = detail;
            path.title = detail;
        }

        function updateEngineState(engine, ready) {
            if (!engine) return;
            engineState = {
                loaded: true,
                ready: ready !== false && Boolean(engine.path),
                path: engine.path || '',
                source: engine.source || 'unknown'
            };
            renderEngineState();
        }

        function updateSelectedFile(file) {
            selectedFile = file || null;
            const meta = document.getElementById('fileMeta');
            if (!selectedFile) {
                meta.textContent = '';
                meta.classList.remove('visible');
                return;
            }
            meta.textContent = lang[currentLang].fileReady + ' · ' + selectedFile.name + ' · ' + formatFileSize(selectedFile.size);
            meta.classList.add('visible');
        }

        function switchLang(language) {
            currentLang = language;
            document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
            document.getElementById('langZh').classList.toggle('active', language === 'zh');
            document.getElementById('langEn').classList.toggle('active', language === 'en');

            const t = lang[language];
            document.title = t.title;
            document.getElementById('subtitle').textContent = t.subtitle;
            document.getElementById('uploadEyebrow').textContent = t.uploadEyebrow;
            document.getElementById('uploadTitle').textContent = t.uploadTitle;
            document.getElementById('uploadNote').textContent = t.uploadNote;
            document.getElementById('selectFileLabel').textContent = t.selectFileLabel;
            document.getElementById('uploadHint').textContent = t.uploadHint;
            document.getElementById('analyzeBtn').textContent = t.analyzeBtn;
            document.getElementById('loadingText').textContent = t.loadingText;
            document.getElementById('privacyText').textContent = t.privacyText;
            document.getElementById('resultsEyebrow').textContent = t.resultsEyebrow;
            document.getElementById('resultsTitle').textContent = t.resultsTitle;
            document.getElementById('resultsNote').textContent = t.resultsNote;
            renderEngineState();
            updateSelectedFile(selectedFile);

            if (lastResult) {
                document.getElementById('summary').innerHTML = '<div class="error-message">' + escapeHtml(t.languageChanged) + '</div>';
                document.getElementById('resultList').innerHTML = '';
                lastResult = null;
            }
        }

        function setBusy(busy, file) {
            document.getElementById('loading').classList.toggle('active', busy);
            document.getElementById('analyzeBtn').disabled = busy;
            document.getElementById('langZh').disabled = busy;
            document.getElementById('langEn').disabled = busy;
            document.getElementById('loadingFile').textContent = busy && file ? file.name + ' · ' + formatFileSize(file.size) : '';
        }

        function showError(message) {
            const section = document.getElementById('resultsSection');
            section.classList.add('visible');
            document.getElementById('summary').innerHTML = '<div class="error-message">' + escapeHtml(message) + '</div>';
            document.getElementById('resultList').innerHTML = '';
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        const apkInput = document.getElementById('apkFile');
        const uploadZone = document.getElementById('uploadZone');
        apkInput.addEventListener('change', () => updateSelectedFile(apkInput.files[0]));
        uploadZone.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); apkInput.click(); }
        });
        ['dragenter', 'dragover'].forEach(type => uploadZone.addEventListener(type, event => {
            event.preventDefault();
            uploadZone.classList.add('dragging');
        }));
        ['dragleave', 'drop'].forEach(type => uploadZone.addEventListener(type, event => {
            event.preventDefault();
            uploadZone.classList.remove('dragging');
        }));
        uploadZone.addEventListener('drop', event => {
            const file = event.dataTransfer && event.dataTransfer.files[0];
            if (file) updateSelectedFile(file);
        });

        fetch('/status', { cache: 'no-store' })
            .then(response => response.json())
            .then(data => updateEngineState(data.engine, data.ready))
            .catch(() => {
                engineState = { loaded: true, ready: false, path: '', source: 'status-unavailable' };
                renderEngineState();
            });

        document.getElementById('uploadForm').addEventListener('submit', async function(event) {
            event.preventDefault();
            const t = lang[currentLang];
            const apkFile = selectedFile || apkInput.files[0];
            if (!apkFile) { alert(t.selectApk); return; }
            if (!/\.(apk|hap)$/i.test(apkFile.name)) { alert(t.invalidApk); return; }

            const formData = new FormData();
            formData.append('apk', apkFile, apkFile.name);
            formData.append('lang', currentLang);
            lastResult = null;
            setBusy(true, apkFile);
            document.getElementById('resultsSection').classList.remove('visible');

            try {
                const response = await fetch('/analyze', { method: 'POST', body: formData });
                const data = await response.json();
                updateEngineState(data.engine, data.engine && Boolean(data.engine.path));
                if (!response.ok || data.error) {
                    showError(data.message || (t.error + ' · HTTP ' + response.status));
                } else {
                    lastResult = data.result;
                    displayResults(data.result);
                }
            } catch (error) {
                showError(t.error + ': ' + error.message);
            } finally {
                setBusy(false, apkFile);
            }
        });
        
        function displayResults(result) {
            const resultsSection = document.getElementById('resultsSection');
            resultsSection.classList.add('visible');
            const t = lang[currentLang];

            const summary = (result && (result['汇总'] || result['summary'])) || {};
            const rawResults = result && (result['结果'] || result['results']);
            const results = Array.isArray(rawResults) ? rawResults : [];
            const scanStatus = String((result && result.scan_status) || 'OK').toUpperCase();
            const scanObserved = (result && result.scan_observed) || {};
            const rawDiagnostics = result && result.scan_diagnostics;
            const scanDiagnostics = Array.isArray(rawDiagnostics) ? rawDiagnostics : [];
            const vmpCounts = {
                LIKELY_VMP: 0,
                VMP_PROTECTED_CLIENT: 0,
                SUSPICIOUS_VM_STRUCTURE: 0,
                VM_LIKE_INTERPRETER: 0
            };
            results.forEach(item => {
                const outcome = String(firstValue(item['VMP状态码'], item['vmp_outcome'])).toUpperCase();
                if (Object.prototype.hasOwnProperty.call(vmpCounts, outcome)) vmpCounts[outcome] += 1;
            });
            const summaryCards = [
                ['total', t.totalSo, firstValue(summary['总so数量'], summary['total_so_count'], 0)],
                ['high', t.highRisk, firstValue(summary['高风险'], summary['high_risk'], 0)],
                ['medium', t.mediumRisk, firstValue(summary['中风险'], summary['medium_risk'], 0)],
                ['low', t.lowRisk, firstValue(summary['低风险'], summary['low_risk'], 0)],
                ['likely', t.likelyVmpCount, vmpCounts.LIKELY_VMP],
                ['client', t.protectedClientCount, vmpCounts.VMP_PROTECTED_CLIENT],
                ['suspicious', t.suspiciousVmpCount, vmpCounts.SUSPICIOUS_VM_STRUCTURE],
                ['runtime', t.runtimeCount, vmpCounts.VM_LIKE_INTERPRETER]
            ];
            const scanStatusClass = ['partial', 'rejected', 'error'].includes(scanStatus.toLowerCase())
                ? scanStatus.toLowerCase()
                : 'ok';
            let summaryHtml = '<div class="scan-status-banner ' + scanStatusClass + '">';
            summaryHtml += '<div class="scan-status-title"><span>' + escapeHtml(t.scanStatus) + ' · ' + escapeHtml(scanStatus) + '</span>';
            summaryHtml += '<span class="scan-status-meta">' + escapeHtml(t.scanAnalyzed) + ' ' + displayValue(firstValue(scanObserved.analyzed_so_count, results.length));
            summaryHtml += ' · ' + escapeHtml(t.scanSkipped) + ' ' + displayValue(firstValue(scanObserved.skipped_so_count, 0)) + '</span></div>';
            if (scanDiagnostics.length > 0) {
                summaryHtml += '<div class="scan-status-meta">' + escapeHtml(t.scanDiagnostics) + '</div><ul class="scan-diagnostics">';
                scanDiagnostics.slice(0, 8).forEach(diagnostic => {
                    const code = firstValue(diagnostic.code, 'SCAN_DIAGNOSTIC');
                    const message = firstValue(diagnostic.message, diagnostic.detail);
                    const entry = firstValue(diagnostic.entry, '');
                    summaryHtml += '<li><strong>' + displayValue(code) + '</strong> · ' + displayValue(message);
                    if (entry) summaryHtml += ' · ' + displayValue(entry);
                    summaryHtml += '</li>';
                });
                summaryHtml += '</ul>';
            }
            summaryHtml += '</div>';
            summaryCards.forEach(card => {
                summaryHtml += '<div class="summary-card ' + card[0] + '">';
                summaryHtml += '<div class="summary-label"><span class="summary-dot"></span>' + escapeHtml(card[1]) + '</div>';
                summaryHtml += '<div class="summary-value">' + displayValue(card[2]) + '</div></div>';
            });
            document.getElementById('summary').innerHTML = summaryHtml;

            let resultsHtml = '';

            results.forEach(item => {
                const riskLevel = firstValue(item['风险等级'], item['risk_level']);
                const riskClass = riskLevel === '高' || riskLevel === 'High'
                    ? 'high'
                    : (riskLevel === '中' || riskLevel === 'Medium' ? 'medium' : 'low');
                const displayRisk = riskLevel === '高'
                    ? t.high
                    : (riskLevel === '中' ? t.medium : (riskLevel === '低' ? t.low : riskLevel));
                const soFile = firstValue(item['so文件'], item['so_file']);

                resultsHtml += '<article class="result-item ' + riskClass + '"><details' + (riskClass === 'low' ? '' : ' open') + '>';
                resultsHtml += '<summary class="result-header"><span class="so-identity"><span class="so-icon">SO</span><span>';
                resultsHtml += '<span class="so-name" title="' + escapeHtml(soFile) + '">' + displayValue(soFile) + '</span>';
                resultsHtml += '<span class="so-caption">' + escapeHtml(t.soDetails) + '</span></span></span>';
                resultsHtml += '<span class="header-actions"><span class="risk-level">' + displayValue(displayRisk) + '</span><span class="chevron" aria-hidden="true"></span></span></summary>';
                resultsHtml += '<div class="result-details">';

                if (item['LibChecker'] || item['libchecker']) {
                    const lc = item['LibChecker'] || item['libchecker'];
                    resultsHtml += '<div class="libchecker-info">';
                    resultsHtml += '<span class="detail-label">' + escapeHtml(t.knownComponent) + '</span> ';
                    resultsHtml += '<strong class="libchecker-name">' + displayValue(firstValue(lc['名称'], lc['name'])) + '</strong>';
                    const team = firstValue(lc['团队'], lc['team']);
                    const description = firstValue(lc['描述'], lc['description']);
                    if (team) {
                        resultsHtml += '<span class="libchecker-team">(' + displayValue(team) + ')</span>';
                    }
                    if (description) {
                        resultsHtml += '<div class="libchecker-desc">' + displayValue(description) + '</div>';
                    }
                    resultsHtml += '</div>';
                }

                resultsHtml += '<div class="overview-grid">';
                resultsHtml += '<div class="detail-item"><span class="detail-label">' + escapeHtml(t.detectionResult) + '</span><br>' + displayValue(firstValue(item['检测结果'], item['detection_result'])) + '</div>';
                resultsHtml += '<div class="detail-item"><span class="detail-label">' + escapeHtml(t.description) + '</span><br>' + displayValue(firstValue(item['说明'], item['description'])) + '</div>';
                resultsHtml += '</div>';

                const rawSuspiciousPoints = firstValue(item['可疑点'], item['suspicious_points'], []);
                const suspiciousPoints = Array.isArray(rawSuspiciousPoints) ? rawSuspiciousPoints : [];
                if (suspiciousPoints.length > 0) {
                    resultsHtml += '<div class="suspicious-points"><span class="detail-label">' + escapeHtml(t.suspiciousPoints) + '</span><ul>';
                    suspiciousPoints.forEach(point => { resultsHtml += '<li>' + displayValue(point) + '</li>'; });
                    resultsHtml += '</ul></div>';
                }

                const rawEntryPreviews = firstValue(item['入口预览'], item['entry_previews'], []);
                const entryPreviews = Array.isArray(rawEntryPreviews) ? rawEntryPreviews : [];
                if (entryPreviews.length > 0) {
                    resultsHtml += '<div class="entry-previews"><span class="detail-label">' + escapeHtml(t.entryPreview) + '</span>';
                    entryPreviews.forEach(entry => {
                        resultsHtml += '<div class="entry-preview"><strong>' + displayValue(firstValue(entry['名称'], entry['name'])) + '</strong> · ';
                        resultsHtml += escapeHtml(t.address) + ': ' + displayValue(firstValue(entry['地址'], entry['address'])) + '<br>';
                        resultsHtml += escapeHtml(t.preview) + ': ' + displayValue(firstValue(entry['预览'], entry['preview'])) + '</div>';
                    });
                    resultsHtml += '</div>';
                }

                const rawLinkerOutcome = firstMeaningfulValue(item['自定义Linker状态码'], item['custom_linker_outcome']);
                const linkerOutcome = String(rawLinkerOutcome || '').trim().toUpperCase();
                const backendLinkerJudgment = firstMeaningfulValue(item['自定义Linker判断'], item['custom_linker_judgment']);
                const actionableLinkerOutcomes = new Set(['CUSTOM_LOADER_COMPONENT', 'LIKELY_CUSTOM_LINKER_PROTECTION']);
                // An explicit hook/inspection outcome always wins over a stale legacy judgment.
                // In particular, Pine must never be presented as custom-Linker protection.
                const isHookInspectionOnly = linkerOutcome === 'ELF_INSPECTION_OR_HOOK';
                const showCustomLinker = !isHookInspectionOnly &&
                    (actionableLinkerOutcomes.has(linkerOutcome) || backendLinkerJudgment !== '');
                if (showCustomLinker) {
                    const isLoaderComponent = linkerOutcome === 'CUSTOM_LOADER_COMPONENT';
                    const isLikelyProtection = linkerOutcome === 'LIKELY_CUSTOM_LINKER_PROTECTION';
                    const linkerJudgment = isLoaderComponent
                        ? t.customLinkerComponentJudgment
                        : (firstMeaningfulValue(backendLinkerJudgment, isLikelyProtection ? t.customLinkerProtectionJudgment : ''));
                    const linkerConfidence = firstMeaningfulValue(item['自定义Linker置信度'], item['custom_linker_confidence']);
                    const newLoaderScore = firstMeaningfulValue(item['自定义Linker装载器分数'], item['custom_linker_loader_score']);
                    const legacyLinkerScore = firstMeaningfulValue(item['自定义Linker分数'], item['custom_linker_score']);
                    const linkerLoaderScore = firstMeaningfulValue(newLoaderScore, legacyLinkerScore);
                    const linkerProtectionScore = firstMeaningfulValue(item['自定义Linker加固分数'], item['custom_linker_protection_score']);
                    const linkerEvidenceCodes = firstMeaningfulValue(item['自定义Linker证据'], item['custom_linker_evidence']);
                    const linkerEvidenceCounts = firstMeaningfulValue(item['自定义Linker证据计数'], item['custom_linker_evidence_counts']);
                    const linkerEvidence = linkerEvidenceCounts !== ''
                        ? { codes: linkerEvidenceCodes, counts: linkerEvidenceCounts }
                        : linkerEvidenceCodes;
                    const loaderScoreLabel = newLoaderScore !== '' ? t.customLinkerLoaderScore : t.customLinkerScore;

                    resultsHtml += '<div class="custom-linker-info' + (isLikelyProtection ? ' outcome-protection' : '') + '">';
                    resultsHtml += '<div class="custom-linker-headline"><span class="detail-label">' + escapeHtml(t.customLinkerJudgment) + '</span>' + displayValue(linkerJudgment);
                    if (linkerOutcome !== '') {
                        resultsHtml += '<span class="custom-linker-outcome-code">' + escapeHtml(t.customLinkerOutcome) + ' · ' + displayValue(linkerOutcome) + '</span>';
                    }
                    resultsHtml += '</div><div class="custom-linker-metrics">';
                    resultsHtml += renderCustomLinkerMetric(t.customLinkerConfidence, linkerConfidence, false);
                    resultsHtml += renderCustomLinkerMetric(loaderScoreLabel, linkerLoaderScore, true);
                    resultsHtml += renderCustomLinkerMetric(t.customLinkerProtectionScore, linkerProtectionScore, true);
                    resultsHtml += '</div>';
                    resultsHtml += renderCustomLinkerEvidence(t.customLinkerEvidence, linkerEvidence);
                    resultsHtml += '</div>';
                }

                const rawVmpJudgment = firstValue(item['VMP判断'], item['vmp_judgment']);
                if (rawVmpJudgment !== '') {
                    const vmpJudgment = rawVmpJudgment;
                    const vmpOutcome = firstValue(item['VMP状态码'], item['vmp_outcome']);
                    const vmpConfidence = firstValue(item['VMP置信度'], item['vmp_confidence']);
                    const vmpProfile = firstValue(item['VMP类型'], item['vmp_profile']);
                    const vmpObservable = firstValue(item['VMP可观测'], item['vmp_observable']);
                    const observableText = vmpObservable === true || vmpObservable === 'true'
                        ? t.yes
                        : (vmpObservable === false || vmpObservable === 'false' ? t.no : '—');

                    resultsHtml += '<div class="vmp-info ' + classifyVmpOutcome(vmpOutcome) + '">';
                    resultsHtml += '<div class="vmp-headline"><span class="detail-label">' + escapeHtml(t.vmpJudgment) + '</span>' + displayValue(vmpJudgment);
                    resultsHtml += '<span class="vmp-outcome-code">' + escapeHtml(t.vmpOutcome) + ' · ' + displayValue(vmpOutcome) + '</span></div>';
                    resultsHtml += '<div class="vmp-axis-grid">';
                    resultsHtml += renderVmpMetric(t.vmpConfidence, vmpConfidence);
                    resultsHtml += renderVmpMetric(t.vmpProfile, vmpProfile);
                    resultsHtml += renderVmpMetric(t.vmpScore, formatScore(firstValue(item['VMP分数'], item['vmp_score'])));
                    resultsHtml += renderVmpMetric(t.vmStructureScore, formatScore(firstValue(item['VM结构分数'], item['vm_structure_score'])));
                    resultsHtml += renderVmpMetric(t.protectionIntentScore, formatScore(firstValue(item['保护意图分数'], item['protection_intent_score'])));
                    resultsHtml += renderVmpMetric(t.alternativePenalty, formatScore(firstValue(item['替代解释扣分'], item['alternative_penalty'])));
                    resultsHtml += renderVmpMetric(t.vmpCoverage, formatCoverage(firstValue(item['VMP扫描覆盖率'], item['vmp_scan_coverage'])));
                    resultsHtml += renderVmpMetric(t.vmpObservable, observableText);
                    resultsHtml += '</div>';

                    const providerEvidence = item['VMP关联证据'] || item['vmp_provider_evidence'];
                    if (providerEvidence && typeof providerEvidence === 'object') {
                        const providerSo = firstValue(providerEvidence['VMP提供库'], providerEvidence['provider_so']);
                        const neededLibrary = firstValue(providerEvidence['DT_NEEDED'], providerEvidence['needed_library']);
                        const rawSharedSymbols = firstValue(providerEvidence['共享符号'], providerEvidence['shared_symbols'], []);
                        const sharedSymbols = Array.isArray(rawSharedSymbols) ? rawSharedSymbols : [rawSharedSymbols];
                        resultsHtml += '<div class="provider-evidence">';
                        resultsHtml += '<div><span class="detail-label">' + escapeHtml(t.vmpDependencyEvidence) + '</span></div>';
                        resultsHtml += '<div class="vmp-metric-grid">';
                        resultsHtml += renderVmpMetric(t.vmpProvider, providerSo);
                        resultsHtml += renderVmpMetric(t.neededLibrary, neededLibrary);
                        resultsHtml += '</div><div class="provider-symbols"><span class="detail-label">' + escapeHtml(t.sharedSymbols) + '</span><br>';
                        resultsHtml += displayValue(sharedSymbols.filter(Boolean).join(' · '));
                        resultsHtml += '</div></div>';
                    }

                    const runtimeAlternative = item['运行时替代解释'] || item['runtime_alternative'];
                    if (runtimeAlternative && typeof runtimeAlternative === 'object') {
                        const runtimeFamily = firstValue(runtimeAlternative['类型'], runtimeAlternative['family']);
                        const runtimeClassesValue = firstValue(runtimeAlternative['独立证据类别数'], runtimeAlternative['evidence_classes']);
                        const runtimeClasses = Number(runtimeClassesValue);
                        const runtimeConfirmedValue = firstValue(runtimeAlternative['已确认'], runtimeAlternative['confirmed']);
                        const runtimeConfirmed = runtimeConfirmedValue === true || runtimeConfirmedValue === 'true' ||
                            (Number.isFinite(runtimeClasses) && runtimeClasses >= 2);
                        const runtimeIdentityHits = firstValue(runtimeAlternative['身份字符串命中'], runtimeAlternative['raw_identity_hits']);
                        const runtimeImportHits = firstValue(runtimeAlternative['导入API命中'], runtimeAlternative['import_api_hits']);

                        resultsHtml += '<div class="runtime-evidence' + (runtimeConfirmed ? ' confirmed' : '') + '">';
                        resultsHtml += '<div><span class="detail-label">' + t.runtimeEvidence + '</span></div>';
                        resultsHtml += '<div class="vmp-metric-grid">';
                        resultsHtml += renderVmpMetric(t.runtimeFamily, runtimeFamily);
                        resultsHtml += renderVmpMetric(t.runtimeEvidenceClasses, runtimeClassesValue);
                        resultsHtml += renderVmpMetric(t.runtimeConfirmed, runtimeConfirmed ? t.yes : t.no);
                        resultsHtml += renderVmpMetric(t.runtimeRawIdentityHits, runtimeIdentityHits);
                        resultsHtml += renderVmpMetric(t.runtimeImportApiHits, runtimeImportHits);
                        resultsHtml += '</div>';
                        resultsHtml += '<div class="runtime-evidence-status">' + escapeHtml(runtimeConfirmed ? t.runtimeConfirmedHint : t.runtimeWeakHint) + '</div>';
                        resultsHtml += '<div class="runtime-evidence-rule">' + escapeHtml(t.runtimeEvidenceRule) + '</div></div>';
                    }

                    resultsHtml += '<div class="vmp-score-note">' + escapeHtml(t.vmpScoreNote) + '</div>';

                    const vmpMetrics = item['VMP扫描指标'] || item['vmp_metrics'] || {};
                    if (vmpMetrics && typeof vmpMetrics === 'object' && Object.keys(vmpMetrics).length > 0) {
                        resultsHtml += '<details class="vmp-details" open><summary>' + escapeHtml(t.vmpMetrics) + '</summary><div class="vmp-metric-grid">';
                        resultsHtml += renderVmpMetric(t.executableBytes, firstValue(vmpMetrics['可执行字节'], vmpMetrics['executable_bytes']));
                        resultsHtml += renderVmpMetric(t.scannedBytes, firstValue(vmpMetrics['扫描字节'], vmpMetrics['scanned_bytes']));
                        resultsHtml += renderVmpMetric(t.decodedCandidateBytes, firstValue(vmpMetrics['候选反汇编字节'], vmpMetrics['decoded_candidate_bytes']));
                        resultsHtml += renderVmpMetric(t.rawIndirectTransfers, firstValue(vmpMetrics['原始间接转移'], vmpMetrics['raw_indirect_transfers']));
                        resultsHtml += renderVmpMetric(t.uniqueCandidates, firstValue(vmpMetrics['去重候选'], vmpMetrics['unique_candidates']));
                        resultsHtml += renderVmpMetric(t.strongCandidates, firstValue(vmpMetrics['强候选'], vmpMetrics['strong_candidates']));
                        resultsHtml += renderVmpMetric(t.mediumCandidates, firstValue(vmpMetrics['中候选'], vmpMetrics['medium_candidates']));
                        resultsHtml += renderVmpMetric(t.dominantVipSites, firstValue(vmpMetrics['共享VPC最大候选数'], vmpMetrics['dominant_vip_sites']));
                        resultsHtml += renderVmpMetric(t.maxClusterSites, firstValue(vmpMetrics['4KB最大聚类数'], vmpMetrics['max_cluster_sites_4k']));
                        resultsHtml += '</div></details>';
                    }

                    const rawFeatures = item['VMP特征'] || item['vmp_features'];
                    const vmpFeatures = Array.isArray(rawFeatures) ? rawFeatures : [];
                    if (vmpFeatures.length > 0) {
                        resultsHtml += '<div class="vmp-details"><span class="detail-label">' + escapeHtml(t.vmpFeatures) + '</span><ul>';
                        vmpFeatures.forEach(feature => { resultsHtml += '<li>' + displayValue(feature) + '</li>'; });
                        resultsHtml += '</ul></div>';
                    }

                    const rawCandidates = item['VMP候选点'] || item['vmp_candidates'];
                    const vmpCandidates = Array.isArray(rawCandidates) ? rawCandidates : [];
                    if (vmpCandidates.length > 0) {
                        resultsHtml += '<details class="vmp-details"><summary>' + escapeHtml(t.vmpCandidates) + ' · ' + vmpCandidates.length + '</summary>';
                        vmpCandidates.forEach((candidate, index) => {
                            const address = firstValue(candidate['地址'], candidate['address']);
                            const region = firstValue(candidate['区域'], candidate['region']);
                            const kind = firstValue(candidate['类型'], candidate['kind']);
                            const strength = firstValue(candidate['强度'], candidate['strength']);
                            const vpc = firstValue(candidate['VPC寄存器'], candidate['vpc_reg']);
                            const opcode = firstValue(candidate['opcode寄存器'], candidate['opcode_reg']);
                            const target = firstValue(candidate['target寄存器'], candidate['target_reg']);
                            const rawTraits = candidate['特征'] || candidate['traits'];
                            const traits = Array.isArray(rawTraits) ? rawTraits : [];
                            resultsHtml += '<div class="vmp-candidate"><strong>#' + (index + 1) + ' ' + displayValue(address) + '</strong><br>';
                            resultsHtml += '<span class="detail-label">' + escapeHtml(t.candidateRegion) + '</span> ' + displayValue(region) + ' &nbsp; ';
                            resultsHtml += '<span class="detail-label">' + escapeHtml(t.candidateKind) + '</span> ' + displayValue(kind) + ' &nbsp; ';
                            resultsHtml += '<span class="detail-label">' + escapeHtml(t.candidateStrength) + '</span> ' + displayValue(strength);
                            resultsHtml += '<div class="vmp-registers">VPC=' + displayValue(vpc) + ' / opcode=' + displayValue(opcode) + ' / target=' + displayValue(target) + '</div>';
                            if (traits.length > 0) {
                                resultsHtml += '<div><span class="detail-label">' + escapeHtml(t.candidateTraits) + '</span> ' + traits.map(displayValue).join(', ') + '</div>';
                            }
                            resultsHtml += '</div>';
                        });
                        resultsHtml += '</details>';
                    }

                    const vmpAlternative = firstValue(item['VMP替代解释'], item['vmp_alternative_explanation']);
                    if (vmpAlternative) {
                        resultsHtml += '<div class="vmp-alternative"><span class="detail-label">' + escapeHtml(t.vmpAlternative) + '</span> ' + displayValue(vmpAlternative) + '</div>';
                    }
                    const vmpLimitation = firstValue(item['VMP分析限制'], item['vmp_limitation']);
                    if (vmpLimitation) {
                        resultsHtml += '<div class="vmp-limitation"><span class="detail-label">' + escapeHtml(t.vmpLimitation) + '</span> ' + displayValue(vmpLimitation) + '</div>';
                    }
                    resultsHtml += '</div>';
                }

                resultsHtml += '<div class="detail-item suggestion"><span class="detail-label">' + escapeHtml(t.suggestion) + '</span><br>' + displayValue(firstValue(item['建议'], item['suggestion'])) + '</div>';
                resultsHtml += '</div></details></article>';
            });
            if (results.length === 0) resultsHtml = '<div class="panel empty-state">' + escapeHtml(t.emptyResults) + '</div>';
            document.getElementById('resultList').innerHTML = resultsHtml;
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    </script>
</body>
</html>
'''


def run_server():
    server = BoundedThreadingHTTPServer((HOST, PORT), RequestHandler)
    print(f"\n[OK] 服务器运行在 http://{HOST}:{PORT}", flush=True)
    print(
        f"[OK] 最大上传 {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB，"
        f"并发扫描 {MAX_CONCURRENT_SCANS}，并发连接 {MAX_ACTIVE_CONNECTIONS}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    run_server()
