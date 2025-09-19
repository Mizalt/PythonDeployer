# utils.py
import subprocess
import socket
import logging
import asyncio
import sys
import shlex

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def decode_windows_output(byte_string: bytes) -> str:
    """
    Пытается декодировать байтовую строку от консольной программы Windows,
    перебирая наиболее вероятные кодировки.
    """
    if not byte_string:
        return ""
    # Наиболее вероятные кодировки для русской Windows
    encodings_to_try = ['cp866', 'utf-8', 'utf-16-le', 'cp1251']
    for enc in encodings_to_try:
        try:
            return byte_string.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    # Если ничего не подошло, возвращаем как есть с игнорированием ошибок
    return byte_string.decode('utf-8', errors='ignore').strip()


async def run_command_async(command: list, cwd: str = None):
    """
    АСИНХРОННО выполняет команду. Принимает список аргументов.
    """
    logging.info(f"Executing async command: '{' '.join(command)}' in '{cwd or 'default dir'}'")
    process = await asyncio.create_subprocess_exec( # Изменить на create_subprocess_exec
        *command, # Распаковать список
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )

    # Читаем stdout и stderr параллельно
    async def read_stream(stream, stream_name):
        while True:
            line = await stream.readline()
            if line:
                # --- Используем функцию декодирования ---
                decoded_line = decode_windows_output(line)
                yield f"[{stream_name}] {decoded_line}"
            else:
                break

    # Объединяем асинхронные генераторы
    async def merge_streams():
        async for item in read_stream(process.stdout, 'STDOUT'):
            yield item
        async for item in read_stream(process.stderr, 'STDERR'):
            yield item

    async for log_line in merge_streams():
        yield log_line

    await process.wait()
    if process.returncode != 0:
        yield f"[ERROR] Command exited with code {process.returncode}"
        raise subprocess.CalledProcessError(process.returncode, command)


def run_command_sync(command: list[str], cwd: str = None, timeout: int = 30, use_shell: bool = False) -> tuple[int, str, str]:
    """
    СИНХРОННО выполняет команду. Принимает список аргументов.
    """
    logging.info(f"Executing command: '{' '.join(command)}' in '{cwd or 'default dir'}' with timeout {timeout}s")
    try:
        process = subprocess.run(
            command if not use_shell else ' '.join(command),  # Если use_shell, то объединяем в строку
            shell=use_shell,
            capture_output=True,
            cwd=cwd,
            timeout=timeout,
            check=False # Чтобы не выбрасывать исключение при ненулевом коде возврата
        )

        stdout_str = decode_windows_output(process.stdout)
        stderr_str = decode_windows_output(process.stderr)

        if process.returncode != 0:
            error_message = stderr_str if stderr_str else stdout_str
            logging.error(f"Command '{command}' failed with code {process.returncode}")
            logging.error(f"Error Output: {error_message}")
        else:
            logging.info(f"Command '{command}' executed successfully. Stdout: {stdout_str[:500]}...")

        return process.returncode, stdout_str, stderr_str

    except subprocess.TimeoutExpired:
        logging.error(f"Command '{command}' timed out after {timeout} seconds.")
        return -1, "", "Command timed out."
    except Exception as e:
        logging.error(f"Failed to execute command '{command}': {e}")
        return -1, "", str(e)

def find_free_port(start_port: int, existing_ports: set) -> int:
    """Находит первый свободный TCP-порт, начиная с start_port."""
    port = start_port
    while True:
        if port in existing_ports:
            port += 1
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
        port += 1

def run_command_detached(command: str, cwd: str = None):
    """
    Запускает команду в новом, полностью отсоединенном процессе.
    Не ждет ее завершения и не получает stdout/stderr.
    Идеально для перезапуска служб, чтобы не убить родительский процесс.
    """
    logging.info(f"Executing detached command: '{command}' in '{cwd or 'default dir'}'")
    # DETACHED_PROCESS работает только в Windows
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.DETACHED_PROCESS

    subprocess.Popen(command, shell=True, cwd=cwd, creationflags=creationflags,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info(f"Detached command sent.")