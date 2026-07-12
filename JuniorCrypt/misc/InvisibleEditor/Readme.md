# Invisible Editor

Challenge file `invisible_editor.docx` is a standard Office Open XML (Word DOCX) document. 
Unzipping the archive reveals `customXml/item1.xml` containing a `<revisionLog>` of document edits.

Reconstructing the text insertion at revision step `20` yields the flag.

## Exploitation Steps

1. Extract custom XML properties:
   ```bash
   unzip invisible_editor.docx customXml/item1.xml
   ```
2. Locate step 20 in `customXml/item1.xml` which inserts the full flag:
   ```xml
   <revision step="20" author="Invisible Editor" at="2026-02-19T10:20:00Z">
       ...
       <inserted>
           ...
           <chunk>grodno{F1@g_W@5_H3r3_0nc3}</chunk>
       </inserted>
   </revision>
   ```
3. Extract flag: `grodno{F1@g_W@5_H3r3_0nc3}`
