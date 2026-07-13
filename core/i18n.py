import json
import os

_translations = {}
_current_lang = "es"

def set_language(lang_code):
    global _translations, _current_lang
    _current_lang = lang_code
    
    if lang_code == "es":
        _translations = {} # Spanish is hardcoded as default in source code
        return
        
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    locale_path = os.path.join(base_dir, "locales", f"{lang_code}.json")
    
    if os.path.exists(locale_path):
        try:
            with open(locale_path, "r", encoding="utf-8") as f:
                _translations = json.load(f)
        except Exception as e:
            print(f"[!] Error loading language '{lang_code}': {e}")
            _translations = {}
    else:
        _translations = {}

def _(text):
    """
    Translate text using the loaded dictionary.
    If translation is not found, returns the original text.
    """
    return _translations.get(text, text)
