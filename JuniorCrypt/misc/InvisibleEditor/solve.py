import xml.etree.ElementTree as ET
import zipfile

def main():
    docx_path = 'invisible_editor.docx'
    with zipfile.ZipFile(docx_path) as z:
        xml_data = z.read('customXml/item1.xml')
    
    root = ET.fromstring(xml_data)
    revisions = root.findall('revision')
    for rev in revisions:
        if rev.attrib['step'] == '20':
            inserted = [c.text if c.text else '' for c in rev.find('inserted').findall('chunk')]
            ins_str = ''.join(inserted)
            # Find flag pattern inside the string
            import re
            flag_match = re.search(r'grodno\{.*?\}', ins_str)
            if flag_match:
                print(flag_match.group(0))
                break

if __name__ == '__main__':
    main()
