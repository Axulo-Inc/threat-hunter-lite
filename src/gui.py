import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json

class ThreatHunterGUI:
    """Simple GUI for ThreatHunter Lite"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("ThreatHunter Lite v1.0")
        self.root.geometry("800x600")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="ThreatHunter Lite", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # File selection
        ttk.Label(main_frame, text="Select Log File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.file_path, width=50).grid(row=1, column=1, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=1, column=2, pady=5)
        
        # Log type selection
        ttk.Label(main_frame, text="Log Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.log_type = tk.StringVar(value="windows")
        ttk.Combobox(main_frame, textvariable=self.log_type, 
                    values=["windows", "linux"]).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Analyze button
        ttk.Button(main_frame, text="Analyze Logs", 
                  command=self.analyze_logs).grid(row=3, column=0, columnspan=3, pady=10)
        
        # Results area
        ttk.Label(main_frame, text="Analysis Results:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.results_text = scrolledtext.ScrolledText(main_frame, height=20, width=80)
        self.results_text.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
    
    def browse_file(self):
        """Browse for log file"""
        filename = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.file_path.set(filename)
    
    def analyze_logs(self):
        """Analyze the selected log file"""
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a log file")
            return
        
        try:
            # Import here to avoid circular imports
            from analyzer import LogAnalyzer
            from reporter import ReportGenerator
            
            # Parse logs based on type
            analyzer = LogAnalyzer()
            if self.log_type.get() == "windows":
                logs = analyzer.parse_windows_logs(self.file_path.get())
            else:
                logs = analyzer.parse_linux_logs(self.file_path.get())
            
            if not logs:
                messagebox.showwarning("Warning", "No logs could be parsed from the file")
                return
            
            # Analyze logs
            results = analyzer.analyze_logs(logs)
            
            # Display results
            report = ReportGenerator.generate_text_report(results)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, report)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
