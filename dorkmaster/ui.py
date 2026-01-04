# ui.py - GUI for DorkStrike PRO

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
from scanner import DorkScanner
from patterns import DorkPatterns

class DorkStrikeUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DorkStrike PRO - Продвинутый сканер Google Dork")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Initialize scanner
        self.scanner = None
        self.scanning = False
        self.scan_thread = None

        # Findings storage for filtering
        self.all_findings = []

        # Create GUI elements
        self.create_widgets()

        # Initialize patterns for category info
        self.patterns = DorkPatterns()

        # Findings storage for filtering
        self.all_findings = []
        self.pattern_search_var = tk.StringVar()
        self.verification_search_var = tk.StringVar()

    def create_widgets(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="DorkStrike PRO", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Настройки сканирования", padding="10")
        input_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)

        # Target domain
        ttk.Label(input_frame, text="Целевой домен:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.domain_var = tk.StringVar()
        self.domain_entry = ttk.Entry(input_frame, textvariable=self.domain_var, width=50)
        self.domain_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # Category selection
        ttk.Label(input_frame, text="Категория паттернов:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.category_var = tk.StringVar(value="ALL")
        category_combo = ttk.Combobox(input_frame, textvariable=self.category_var,
                                    values=["ALL", "CRYPTO", "SECRETS", "VULNERABILITIES"], state="readonly")
        category_combo.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=5)

        # Threads and Depth
        ttk.Label(input_frame, text="Потоки:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.threads_var = tk.IntVar(value=10)
        threads_spin = tk.Spinbox(input_frame, from_=1, to=50, textvariable=self.threads_var, width=10)
        threads_spin.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=5)

        ttk.Label(input_frame, text="Глубина:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.depth_var = tk.IntVar(value=3)
        depth_spin = tk.Spinbox(input_frame, from_=1, to=10, textvariable=self.depth_var, width=10)
        depth_spin.grid(row=3, column=1, sticky=tk.W, padx=(0, 10), pady=5)

        # Search Engines
        ttk.Label(input_frame, text="Поисковые системы:").grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        engines_frame = ttk.Frame(input_frame)
        engines_frame.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5)

        self.engine_vars = {}
        engines = ['google', 'duckduckgo', 'bing', 'shodan', 'wayback']
        engine_names = {'google': 'Google', 'duckduckgo': 'DuckDuckGo', 'bing': 'Bing', 'shodan': 'Shodan', 'wayback': 'Wayback'}
        for i, engine in enumerate(engines):
            var = tk.BooleanVar(value=(engine == 'google'))  # Google enabled by default
            self.engine_vars[engine] = var
            ttk.Checkbutton(engines_frame, text=engine_names[engine], variable=var).grid(row=0, column=i, sticky=tk.W, padx=(0, 10))

        # Custom Dorks
        ttk.Label(input_frame, text="Пользовательские дорки:").grid(row=5, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.custom_dorks_text = scrolledtext.ScrolledText(input_frame, height=3, width=50)
        self.custom_dorks_text.grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5)
        self.custom_dorks_text.insert(tk.END, "# Введите по одному дорку на строку\n# Пример: site:{target} filetype:env")

        # Proxies
        ttk.Label(input_frame, text="Прокси:").grid(row=6, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        proxies_frame = ttk.Frame(input_frame)
        proxies_frame.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5)
        proxies_frame.columnconfigure(0, weight=1)

        self.proxies_text = scrolledtext.ScrolledText(proxies_frame, height=3, width=50)
        self.proxies_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.proxies_text.insert(tk.END, "# Введите по одному прокси на строку\n# Пример: http://proxy1:port\n# https://proxy2:port")

        proxy_buttons_frame = ttk.Frame(proxies_frame)
        proxy_buttons_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))

        ttk.Button(proxy_buttons_frame, text="Загрузить прокси", command=self.load_proxies).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(proxy_buttons_frame, text="Сохранить прокси", command=self.save_proxies).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(proxy_buttons_frame, text="Тестировать прокси", command=self.test_proxies).grid(row=0, column=2)

        # Options frame
        options_frame = ttk.Frame(input_frame)
        options_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.js_rendering_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Использовать JavaScript рендеринг", variable=self.js_rendering_var).grid(row=0, column=0, sticky=tk.W)

        self.verify_api_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Проверять API ключи", variable=self.verify_api_var).grid(row=0, column=1, sticky=tk.W, padx=(20, 0))

        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))

        self.start_button = ttk.Button(button_frame, text="Начать сканирование", command=self.start_scan)
        self.start_button.grid(row=0, column=0, padx=(0, 10))

        self.stop_button = ttk.Button(button_frame, text="Остановить сканирование", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=(0, 10))

        self.local_scan_button = ttk.Button(button_frame, text="Сканирование локальных файлов", command=self.local_scan)
        self.local_scan_button.grid(row=0, column=2, padx=(0, 10))

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Результаты", padding="10")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Results notebook
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Findings tab
        findings_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(findings_frame, text="Найденные")

        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)

        # Findings treeview
        columns = ("Тип", "Паттерн", "URL", "Совпадение", "Проверка")
        self.findings_tree = ttk.Treeview(findings_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.findings_tree.heading(col, text=col)
            self.findings_tree.column(col, width=150)

        findings_scrollbar = ttk.Scrollbar(findings_frame, orient=tk.VERTICAL, command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=findings_scrollbar.set)

        self.findings_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        findings_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Log tab
        log_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(log_frame, text="Лог")

        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Statistics
        stats_frame = ttk.LabelFrame(main_frame, text="Статистика", padding="10")
        stats_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        self.stats_labels = {}
        stats = ["Всего URL", "Найдено", "Длительность", "Среднее время ответа"]
        for i, stat in enumerate(stats):
            ttk.Label(stats_frame, text=f"{stat}:").grid(row=0, column=i*2, sticky=tk.W, padx=(0, 5))
            label = ttk.Label(stats_frame, text="0")
            label.grid(row=0, column=i*2+1, sticky=tk.W, padx=(0, 20))
            self.stats_labels[stat] = label

        # Resource classification stats
        ttk.Label(stats_frame, text="Категории ресурсов:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.resource_stats_label = ttk.Label(stats_frame, text="A:0 B:0 C:0 D:0 E:0")
        self.resource_stats_label.grid(row=1, column=1, columnspan=7, sticky=tk.W, padx=(0, 20), pady=(5, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Готов")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E))

    def start_scan(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showerror("Ошибка", "Пожалуйста, введите целевой домен")
            return

        if not self.scanning:
            self.scanning = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.local_scan_button.config(state=tk.DISABLED)

            # Clear previous results
            for item in self.findings_tree.get_children():
                self.findings_tree.delete(item)
            self.log_text.delete(1.0, tk.END)
            self.progress_var.set(0)

            # Get selected search engines
            search_engines = [engine for engine, var in self.engine_vars.items() if var.get()]

            # Get proxies
            proxies_text = self.proxies_text.get(1.0, tk.END).strip()
            proxies = [line.strip() for line in proxies_text.split('\n') if line.strip() and not line.startswith('#')]

            # Get custom dorks
            custom_dorks_text = self.custom_dorks_text.get(1.0, tk.END).strip()
            custom_dorks = [line.strip() for line in custom_dorks_text.split('\n') if line.strip() and not line.startswith('#')]

            # Initialize scanner
            self.scanner = DorkScanner(
                proxies=proxies,
                search_engines=search_engines,
                use_js_rendering=self.js_rendering_var.get(),
                verify_api_keys=self.verify_api_var.get(),
                depth=self.depth_var.get(),
                custom_dorks=custom_dorks
            )

            # Start scan in thread
            self.scan_thread = threading.Thread(
                target=self.run_scan,
                args=(domain, self.category_var.get(), self.threads_var.get())
            )
            self.scan_thread.daemon = True
            self.scan_thread.start()

    def run_scan(self, domain, category, threads):
        try:
            results = self.scanner.scan(
                domain, category, threads,
                self.progress_callback,
                self.log_callback,
                self.finding_callback
            )

            # Update statistics
            self.root.after(0, lambda: self.update_statistics(results))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Сканирование не удалось: {str(e)}"))
        finally:
            self.root.after(0, self.scan_finished)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop_scan()
        self.scan_finished()

    def scan_finished(self):
        self.scanning = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.local_scan_button.config(state=tk.NORMAL)
        self.status_var.set("Сканирование завершено")

    def progress_callback(self, progress):
        self.root.after(0, lambda: self.progress_var.set(progress))

    def log_callback(self, message):
        self.root.after(0, lambda: self.log_text.insert(tk.END, message + "\n"))
        self.root.after(0, lambda: self.log_text.see(tk.END))
        self.root.after(0, lambda: self.status_var.set(message))

    def finding_callback(self, finding_type, pattern, url, match, verification):
        self.all_findings.append((finding_type, pattern, url, match, verification))
        self.populate_findings()

    def populate_findings(self):
        # Clear existing items
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)

        # Populate with all findings
        for finding_type, pattern, url, match, verification in self.all_findings:
            self.findings_tree.insert("", tk.END, values=(finding_type, pattern, url, match, verification))

    def update_statistics(self, results):
        self.stats_labels["Всего URL"].config(text=str(results.get('total_urls', 0)))
        self.stats_labels["Найдено"].config(text=str(results.get('findings_count', 0)))
        self.stats_labels["Длительность"].config(text=f"{results.get('duration', 0):.2f}s")
        self.stats_labels["Среднее время ответа"].config(text=f"{results.get('avg_response_time', 0):.2f}s")

        # Update resource classification stats
        resource_stats = results.get('resource_stats', {})
        stats_text = " | ".join([f"{cat}:{count}" for cat, count in resource_stats.items()])
        self.resource_stats_label.config(text=stats_text)

    def local_scan(self):
        file_paths = filedialog.askopenfilenames(
            title="Выберите файлы для сканирования",
            filetypes=[("Все файлы", "*"), ("Текстовые файлы", "*.txt"), ("Файлы конфигурации", "*.env *.json *.yml")]
        )

        if not file_paths:
            return

        category = self.category_var.get()

        # Clear previous results
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        self.log_text.delete(1.0, tk.END)

        # Initialize scanner
        self.scanner = DorkScanner(verify_api_keys=self.verify_api_var.get())

        # Run local scan
        try:
            results = self.scanner.local_scan(
                file_paths, category,
                self.log_callback,
                self.finding_callback
            )

            # Update statistics
            self.update_statistics(results)
            messagebox.showinfo("Локальное сканирование завершено", f"Просканировано {len(file_paths)} файлов, найдено {results.get('findings_count', 0)} совпадений")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Локальное сканирование не удалось: {str(e)}")

    def load_proxies(self):
        file_path = filedialog.askopenfilename(
            title="Загрузить прокси",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    proxies = f.read()
                self.proxies_text.delete(1.0, tk.END)
                self.proxies_text.insert(tk.END, proxies)
                messagebox.showinfo("Успех", "Прокси загружены успешно")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить прокси: {str(e)}")

    def save_proxies(self):
        file_path = filedialog.asksaveasfilename(
            title="Сохранить прокси",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*")]
        )
        if file_path:
            try:
                proxies = self.proxies_text.get(1.0, tk.END)
                with open(file_path, 'w') as f:
                    f.write(proxies)
                messagebox.showinfo("Успех", "Прокси сохранены успешно")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить прокси: {str(e)}")

    def test_proxies(self):
        proxies_text = self.proxies_text.get(1.0, tk.END).strip()
        proxies = [line.strip() for line in proxies_text.split('\n') if line.strip() and not line.startswith('#')]

        if not proxies:
            messagebox.showwarning("Предупреждение", "Нет прокси для тестирования")
            return

        self.log_callback(f"Тестирование {len(proxies)} прокси...")

        # Test proxies in a thread
        threading.Thread(target=self._test_proxies_thread, args=(proxies,), daemon=True).start()

    def _test_proxies_thread(self, proxies):
        import requests

        working_proxies = []
        total = len(proxies)

        for i, proxy in enumerate(proxies):
            try:
                # Test with a simple request
                response = requests.get('http://httpbin.org/ip', proxies={'http': proxy, 'https': proxy}, timeout=5)
                if response.status_code == 200:
                    working_proxies.append(proxy)
                    self.root.after(0, lambda p=proxy: self.log_callback(f"✓ {p} - Работает"))
                else:
                    self.root.after(0, lambda p=proxy: self.log_callback(f"✗ {p} - Плохой ответ"))
            except:
                self.root.after(0, lambda p=proxy: self.log_callback(f"✗ {p} - Мертвый"))

            # Update progress
            progress = (i + 1) / total * 100
            self.root.after(0, lambda p=progress: self.progress_var.set(p))

        # Update proxy list with only working ones
        working_text = '\n'.join(working_proxies)
        self.root.after(0, lambda: self.proxies_text.delete(1.0, tk.END))
        self.root.after(0, lambda: self.proxies_text.insert(tk.END, working_text))

        self.root.after(0, lambda: self.log_callback(f"Тестирование прокси завершено. {len(working_proxies)}/{total} рабочих прокси сохранено."))
        self.root.after(0, lambda: messagebox.showinfo("Тестирование прокси завершено", f"{len(working_proxies)} из {total} прокси работают."))

if __name__ == "__main__":
    root = tk.Tk()
    app = DorkStrikeUI(root)
    root.mainloop()