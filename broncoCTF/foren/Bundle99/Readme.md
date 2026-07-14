# Bundle 99 - BroncoCTF 2026 (Forensics)

## Deskripsi
Diberikan sebuah file bernama `chall` yang diduga merupakan resource bundle dari aplikasi Krita.

## Analisis & Solusi
1. Identifikasi tipe file `chall` menggunakan command `file`. Didapatkan informasi bahwa file tersebut merupakan file Zip:
   ```bash
   file ./chall
   # ./chall: Zip data (MIME type "application/x-krita-resourcebundle"?)
   ```
2. Ekstrak isi file Zip tersebut. Di dalamnya terdapat preset brush Krita dengan ekstensi `.kpp` (`paintoppresets/Brush 99.kpp`).
3. File `.kpp` merupakan file gambar PNG yang menyimpan metadata konfigurasi brush Krita.
4. Cek metadata file `Brush 99.kpp` menggunakan `exiftool` atau library Python `Pillow`. Metadata tersebut menyimpan konfigurasi XML brush pada field `Preset`.
5. Di dalam XML tag `<param name="brush_definition">`, terdapat teks brush berupa flag:
   ```xml
   <param name="brush_definition" type="string"><![CDATA[<Brush font="Segoe UI,9,-1,5,50,0,0,0,0,0" spacing="0.2" pipe="false" type="kis_text_brush" BrushVersion="2" text="bronco{1m4n4rt15ttru5t}"/> ]]></param>
   ```

Flag yang didapat: `bronco{1m4n4rt15ttru5t}`
