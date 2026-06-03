import textual.widgets
import builtins
import runpy

# Hook fungsi update pada widget Static untuk menangkap teks Flag
original_update = textual.widgets.Static.update

def patched_update(self, renderable):
    if renderable:
        res = str(renderable)
        # Simpan semua teks yang muncul di UI ke file log
        with open("dump_text.txt", "a") as f:
            f.write(f"\n[DUMP] {res}")
        # Jika mengandung kata kunci flag, cetak ke terminal
        if "TCP1P" in res:
            builtins.print(f"\n[!] FLAG DITEMUKAN: {res}\n")
    return original_update(self, renderable)

textual.widgets.Static.update = patched_update

# Jalankan app.py sebagai __main__
runpy.run_path("app.py", run_name="__main__")
