################################################################################################################

# Copyright (c) 2026 by Uwe Martens * www.namecoin.pro * https://dotbit.app

################################################################################################################

import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, Toplevel, OptionMenu, ttk, Canvas
import json
import os
import threading
import time
from datetime import datetime
from signer import Signer
import webbrowser

rpc_user = "XXXXXXX"
rpc_pass = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
NMC_RPC = {'url': 'http://localhost:8336', 'user': rpc_user, 'pass': rpc_pass}

CONFIG_FILE = 'config.json'
LANGUAGES_DIR = 'languages'

AVAILABLE_LANGUAGES = {
	'ar': ' العربية (Arabic)',
	'de': ' Deutsch (German)',
	'en': ' English',
	'es': ' Español (Spanish)',
	'fr': ' Français (French)',
	'hi': ' हिन्दी (Hindi)',
	'id': ' Bahasa Indonesia (Indonesian)',
	'ja': ' 日本語 (Japanese)',
	'ko': ' 한국어 (Korean)',
	'pl': ' Polski (Polish)',
	'pt': ' Português (Portuguese)',
	'ru': ' Русский (Russian)',
	'zh': ' 中文 (Chinese)',
}

class SignGUI:
	def __init__(self, master):
		self.master = master
		self.strings = {}
		self.lang_selected = False
		self.is_lang_prompt = False
		self.load_config_and_language()
		master.title(self._('title'))
		
		self.canvas = Canvas(master, highlightthickness=0)
		self.canvas.pack(fill='both', expand=True)
		self.master.bind("<Configure>", self.resize)
		
		label_font = ("Helvetica", 12, "bold")
		entry_font = ("Helvetica", 10)
		
		self.name_entry = tk.Entry(master, width=50, relief='flat', bd=2, highlightthickness=1, highlightbackground="#a0a0a0", font=entry_font)
		self.message_text = scrolledtext.ScrolledText(master, height=5, relief='flat', bd=2, highlightthickness=1, highlightbackground="#a0a0a0", font=entry_font)
		self.signature_entry = scrolledtext.ScrolledText(master, height=2, wrap='char', relief='flat', bd=2, highlightthickness=1, highlightbackground="#a0a0a0", font=entry_font)
		
		button_font = ("Helvetica", 10, "bold")
		self.button_sign = tk.Button(master, text=self._('button_sign'), command=self.sign_message, state=tk.DISABLED, bg='lightblue', relief='raised', width=10, font=button_font)
		self.button_sign.config(padx=10, pady=5)
		self.button_verify = tk.Button(master, text=self._('button_verify'), command=self.verify_message, state=tk.DISABLED, bg='lightgreen', relief='raised', width=10, font=button_font)
		self.button_verify.config(padx=10, pady=5)
		
		self.footer_text_id = None
		self.label_name_id = None
		self.label_message_id = None
		self.label_signature_id = None
		self.lang_select_label_id = None
		
		self.log = scrolledtext.ScrolledText(master, height=10, relief='flat', bd=2, highlightthickness=1, highlightbackground="#a0a0a0", font=entry_font)
		self.log_insert(self._('log_welcome'))
		
		self.window_ids = {
			'name_entry': self.canvas.create_window(0, 0, anchor='n', window=self.name_entry),
			'message_text': self.canvas.create_window(0, 0, anchor='n', window=self.message_text),
			'signature_entry': self.canvas.create_window(0, 0, anchor='n', window=self.signature_entry),
			'button_sign': self.canvas.create_window(0, 0, anchor='n', window=self.button_sign),
			'button_verify': self.canvas.create_window(0, 0, anchor='n', window=self.button_verify),
			'log': self.canvas.create_window(0, 0, anchor='n', window=self.log),
		}
		self.main_order = ['name_entry', 'message_text', 'signature_entry', 'button_sign', 'button_verify', 'log']
		
		if not self.lang_selected:
			for iid in self.window_ids.values():
				self.canvas.itemconfig(iid, state='hidden')
			self.prompt_language_selection()
		else:
			self.resize(None)
		
		self.signer = None
		self.log_insert(self._('log_loading_wallet'))
		threading.Thread(target=self.load_signer, daemon=True).start()
		
		self.master.after(100, lambda: self.resize(None))

	def open_link(self, url):
		webbrowser.open_new(url)

	def resize(self, event=None):
		width = self.canvas.winfo_width()
		height = self.canvas.winfo_height()
		if width <= 0 or height <= 0:
			return
		
		self.canvas.delete('gradient')
		r1, g1, b1 = 103, 135, 183
		r2, g2, b2 = 255, 255, 255
		for y in range(height):
			pos = (height - y) / height
			if pos <= 0.5:
				r, g, b = r1, g1, b1
			else:
				norm_ratio = (pos - 0.5) / 0.5
				r = int(r1 + (r2 - r1) * norm_ratio)
				g = int(g1 + (g2 - g1) * norm_ratio)
				b = int(b1 + (b2 - b1) * norm_ratio)
			color = f'#{r:02x}{g:02x}{b:02x}'
			self.canvas.create_line(0, y, width, y, fill=color, tags='gradient')
		
		char_widthapprox = width // 8
		self.master.update_idletasks()
		
		if self.is_lang_prompt:
			current_y = height // 4
			label_font = ("Helvetica", 10, "bold")
			
			if self.lang_select_label_id:
				self.canvas.delete(self.lang_select_label_id)
			self.lang_select_label_id = self.canvas.create_text(
				width / 2, 
				current_y, 
				text="Select your language:", 
				fill="#333333", 
				font=label_font, 
				anchor='n'
			)
			text_bbox = self.canvas.bbox(self.lang_select_label_id)
			label_height = text_bbox[3] - text_bbox[1] if text_bbox else 20
			current_y += label_height + 10
			
			self.canvas.coords(self.lang_window_ids['menu'], width / 2, current_y)
			current_y += self.lang_select_menu.winfo_reqheight() + 20
			
			self.canvas.coords(self.lang_window_ids['button'], width / 2, current_y)
		else:
			resp_width = max(40, char_widthapprox - 10)
			self.message_text.config(width=resp_width)
			self.log.config(width=resp_width)
			self.name_entry.config(width=min(50, resp_width))
			self.signature_entry.config(width=resp_width)
			self.master.update_idletasks()
			
			current_y = 30
			label_font = ("Helvetica", 10, "bold")
			
			if self.label_name_id:
				self.canvas.delete(self.label_name_id)
			self.label_name_id = self.canvas.create_text(
				width / 2, 
				current_y, 
				text=self._('label_name'), 
				fill="#333333", 
				font=label_font, 
				anchor='n'
			)
			text_bbox = self.canvas.bbox(self.label_name_id)
			label_height = text_bbox[3] - text_bbox[1] if text_bbox else 20
			current_y += label_height + 10
			
			self.canvas.coords(self.window_ids['name_entry'], width / 2, current_y)
			current_y += self.name_entry.winfo_reqheight() + 20
			
			if self.label_message_id:
				self.canvas.delete(self.label_message_id)
			self.label_message_id = self.canvas.create_text(
				width / 2, 
				current_y, 
				text=self._('label_message'), 
				fill="#333333", 
				font=label_font, 
				anchor='n'
			)
			text_bbox = self.canvas.bbox(self.label_message_id)
			label_height = text_bbox[3] - text_bbox[1] if text_bbox else 20
			current_y += label_height + 10
			
			self.canvas.coords(self.window_ids['message_text'], width / 2, current_y)
			current_y += self.message_text.winfo_reqheight() + 20
			
			if self.label_signature_id:
				self.canvas.delete(self.label_signature_id)
			self.label_signature_id = self.canvas.create_text(
				width / 2, 
				current_y, 
				text=self._('label_signature'), 
				fill="#333333", 
				font=label_font, 
				anchor='n'
			)
			text_bbox = self.canvas.bbox(self.label_signature_id)
			label_height = text_bbox[3] - text_bbox[1] if text_bbox else 20
			current_y += label_height + 10
			
			self.canvas.coords(self.window_ids['signature_entry'], width / 2, current_y)
			current_y += self.signature_entry.winfo_reqheight() + 20
			
			self.canvas.coords(self.window_ids['button_sign'], width / 2 - 100, current_y)
			self.canvas.coords(self.window_ids['button_verify'], width / 2 + 100, current_y)
			current_y += self.button_sign.winfo_reqheight() + 20
			
			self.canvas.coords(self.window_ids['log'], width / 2, current_y)
			current_y += self.log.winfo_reqheight() + 10
			
			if self.footer_text_id:
				self.canvas.delete(self.footer_text_id)
			footer_font = ("Helvetica", 10, "bold")
			self.footer_text_id = self.canvas.create_text(
				width / 2, 
				current_y + 10, 
				text="www.namecoin.pro", 
				fill="white", 
				font=footer_font, 
				anchor='n'
			)
			self.canvas.tag_bind(self.footer_text_id, "<Button-1>", lambda e: self.open_link("https://www.namecoin.pro"))
			self.canvas.tag_bind(self.footer_text_id, "<Enter>", lambda e: self.canvas.config(cursor="hand2"))
			self.canvas.tag_bind(self.footer_text_id, "<Leave>", lambda e: self.canvas.config(cursor=""))
			self.canvas.itemconfig(self.footer_text_id, activefill="lightblue")

	def load_signer(self):
		try:
			self.signer = Signer(NMC_RPC)
			self.master.after(0, lambda: self.log_insert(self._('log_wallet_loaded')))
			self.master.after(0, self.enable_buttons)
		except Exception as e:
			self.master.after(0, lambda: self.log_insert(f"Error loading wallet: {str(e)}"))

	def _(self, key):
		return self.strings.get(key, key)
	
	def load_config_and_language(self):
		print("Loading config and language")
		if os.path.exists(CONFIG_FILE):
			with open(CONFIG_FILE, 'r') as f:
				config = json.load(f)
			lang = config.get('language', 'en')
			self.lang_selected = True
		else:
			lang = 'en'
			self.lang_selected = False
		
		lang_file = os.path.join(LANGUAGES_DIR, f"{lang}.json")
		if os.path.exists(lang_file):
			with open(lang_file, 'r', encoding='utf-8') as f:
				self.strings = json.load(f)
		else:
			messagebox.showerror("Error", f"Language file {lang}.json not found! Falling back to English.")
			self.strings = {}
	
	def prompt_language_selection(self):
		print("Prompting language selection")
		self.is_lang_prompt = True
		self.lang_var = tk.StringVar(value=AVAILABLE_LANGUAGES['en'])
		options = list(AVAILABLE_LANGUAGES.values())
		self.lang_select_menu = OptionMenu(self.master, self.lang_var, *options)
		self.lang_select_menu.config(relief='flat', highlightthickness=1, highlightbackground="#a0a0a0")
		
		def confirm_lang():
			selected_display = self.lang_var.get()
			selected_lang = next(code for code, display in AVAILABLE_LANGUAGES.items() if display == selected_display)
			with open(CONFIG_FILE, 'w') as f:
				json.dump({'language': selected_lang}, f)
			self.load_config_and_language()
			self.master.title(self._('title'))
			self.update_ui_texts()
			self.lang_select_menu.destroy()
			self.lang_select_button.destroy()
			self.is_lang_prompt = False
			for iid in self.window_ids.values():
				self.canvas.itemconfig(iid, state='normal')
			self.resize(None)
		
		button_font = ("Helvetica", 10, "bold")
		self.lang_select_button = tk.Button(self.master, text="OK", command=confirm_lang, bg='white', relief='raised', width=10, font=button_font)
		self.lang_select_button.config(padx=10, pady=5)
		
		self.lang_window_ids = {
			'menu': self.canvas.create_window(0, 0, anchor='n', window=self.lang_select_menu),
			'button': self.canvas.create_window(0, 0, anchor='n', window=self.lang_select_button)
		}
		self.resize(None)
	
	def update_ui_texts(self):
		print("Updating UI texts")
		self.button_sign.config(text=self._('button_sign'))
		self.button_verify.config(text=self._('button_verify'))
		self.log_insert(self._('log_language_changed'))
		self.resize(None)
	
	def log_insert(self, msg):
		self.log.insert(tk.END, f"{datetime.now()}: {msg}\n")
		self.log.see(tk.END)
	
	def enable_buttons(self):
		self.button_sign.config(state=tk.NORMAL)
		self.button_verify.config(state=tk.NORMAL)
	
	def sign_message(self):
		print("Signing message")
		try:
			msg = self.message_text.get("1.0", "end-1c")
			name = self.name_entry.get().strip()
			if not name:
				raise ValueError("Name is required")
			
			addr = self.signer.get_address_from_name(name)
			sig = self.signer.sign(addr, msg)
			
			self.signature_entry.delete("1.0", tk.END)
			self.signature_entry.insert("1.0", sig)
			self.log_insert(self._('log_signed'))
		except Exception as e:
			print(f"Error signing: {str(e)}")
			self.log_insert(str(e))
			messagebox.showerror(self._('error_title'), str(e))
	
	def verify_message(self):
		print("Verifying message")
		try:
			msg = self.message_text.get("1.0", "end-1c")
			name = self.name_entry.get().strip()
			sig = self.signature_entry.get("1.0", "end-1c").strip()
			if not name or not sig:
				raise ValueError("Name and signature are required")
			
			addr = self.signer.get_address_from_name(name)
			valid = self.signer.verify(addr, sig, msg)
			
			if valid:
				messagebox.showinfo(self._('verify_title'), '✅ ' + self._('msg_valid'))
			else:
				messagebox.showinfo(self._('verify_title'), '❌ ' + self._('msg_invalid'))
			self.log_insert(self._('log_verified'))
		except Exception as e:
			print(f"Error verifying: {str(e)}")
			self.log_insert(str(e))
			messagebox.showerror(self._('error_title'), str(e))
	
	def on_closing(self):
		print("Closing GUI")
		if self.signer:
			self.signer.cleanup()
		self.master.destroy()

if __name__ == "__main__":
	print("Starting main")
	root = tk.Tk()
	root.minsize(800, 600)
	style = ttk.Style()
	style.theme_use('clam')
	app = SignGUI(root)
	root.protocol("WM_DELETE_WINDOW", app.on_closing)
	root.mainloop()
