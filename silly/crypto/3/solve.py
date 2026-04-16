#!/usr/bin/env python3
import re
import zipfile
import xml.etree.ElementTree as ET

PPTX_PATH = "sixtotheseven.pptx"


def extract_flag(pptx_path: str) -> str:
    with zipfile.ZipFile(pptx_path) as zf:
        pres = ET.fromstring(zf.read("ppt/presentation.xml"))
        rels = ET.fromstring(zf.read("ppt/_rels/presentation.xml.rels"))

        ns = {"p": "http://schemas.openxmlformats.org/presentationml/2006/main"}
        rid_to_target = {rel.attrib["Id"]: rel.attrib["Target"] for rel in rels}

        chunks = []
        current = ""

        for sld in pres.findall(".//p:sldId", ns):
            rid = sld.attrib[
                "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
            ]
            slide_target = rid_to_target[rid]
            slide_num = int(re.search(r"slide(\d+)\.xml", slide_target).group(1))

            srels = ET.fromstring(zf.read(f"ppt/slides/_rels/slide{slide_num}.xml.rels"))
            image_name = None
            for rel in srels:
                if rel.attrib.get("Type", "").endswith("/image"):
                    image_name = rel.attrib["Target"].split("/")[-1]
                    break

            if image_name == "image4.jpg":
                chunks.append(current)
                current = ""
            elif image_name == "image2.png":
                current += "6"
            elif image_name == "image3.png":
                current += "7"
            else:
                raise ValueError(f"Unexpected image mapping on slide {slide_num}: {image_name}")

        chunks.append(current)

        # Decode: 6 -> 0, 7 -> 1
        out = []
        for chunk in chunks:
            if len(chunk) != 8:
                raise ValueError(f"Unexpected chunk size {len(chunk)} for chunk: {chunk}")
            bits = chunk.replace("6", "0").replace("7", "1")
            out.append(chr(int(bits, 2)))

        return "".join(out)


if __name__ == "__main__":
    flag = extract_flag(PPTX_PATH)
    print(flag)
