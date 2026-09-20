import io
import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from PIL import Image
from werkzeug.datastructures import FileStorage

from meyora_attachments import AttachmentStore


class _FakeResponse:
    output_text = "A test image containing a blue square and no visible text."


class _FakeResponses:
    def create(self, **kwargs):
        return _FakeResponse()


class _FakeOpenAI:
    responses = _FakeResponses()


def _file_storage(name, data, mime):
    return FileStorage(stream=io.BytesIO(data), filename=name, content_type=mime)


def _docx_bytes():
    body = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Hello Meyora DOCX</w:t></w:r></w:p></w:body>
</w:document>"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", body)
        z.writestr("[Content_Types].xml", "<Types/>")
    return out.getvalue()


def _xlsx_bytes():
    workbook = """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
 <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""
    rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Target="worksheets/sheet1.xml"/>
</Relationships>"""
    shared = """<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <si><t>Account</t></si><si><t>MD Anderson</t></si>
</sst>"""
    sheet = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <sheetData>
  <row r="1"><c r="A1" t="s"><v>0</v></c></row>
  <row r="2"><c r="A2" t="s"><v>1</v></c></row>
 </sheetData>
</worksheet>"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        z.writestr("xl/sharedStrings.xml", shared)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        z.writestr("[Content_Types].xml", "<Types/>")
    return out.getvalue()


def main():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        db_path = root / "test.db"

        def db_factory():
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            return conn

        store = AttachmentStore(db_factory, root, _FakeOpenAI())
        principal = {"principal_id": "maya-field", "domain": "field_service"}

        txt = store.create("owner-a", principal, _file_storage("notes.txt", b"hello session", "text/plain"))
        assert txt["status"] == "ready"
        assert "hello session" in store.get(txt["attachment_id"], "owner-a", True)["extracted_text"]

        csv_item = store.create("owner-a", principal, _file_storage("parts.csv", b"part,qty\nP1,3\n", "text/csv"))
        assert "P1" in store.get(csv_item["attachment_id"], "owner-a", True)["extracted_text"]

        docx = store.create("owner-a", principal, _file_storage(
            "brief.docx", _docx_bytes(),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ))
        assert "Hello Meyora DOCX" in store.get(docx["attachment_id"], "owner-a", True)["extracted_text"]

        xlsx = store.create("owner-a", principal, _file_storage(
            "accounts.xlsx", _xlsx_bytes(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ))
        assert "MD Anderson" in store.get(xlsx["attachment_id"], "owner-a", True)["extracted_text"]

        image_buffer = io.BytesIO()
        Image.new("RGB", (64, 64), (0, 0, 255)).save(image_buffer, format="JPEG")
        image = store.create("owner-a", principal, _file_storage("photo.jpg", image_buffer.getvalue(), "image/jpeg"))
        assert image["status"] == "ready"
        assert "blue square" in store.get(image["attachment_id"], "owner-a", True)["extracted_text"]

        manifest, context = store.context_for_ids(
            "owner-a",
            [txt["attachment_id"], csv_item["attachment_id"], docx["attachment_id"], xlsx["attachment_id"], image["attachment_id"]],
        )
        assert len(manifest) == 5
        assert "MD Anderson" in context
        assert "blue square" in context

        try:
            store.get(txt["attachment_id"], "owner-b")
            raise AssertionError("cross-owner attachment access unexpectedly succeeded")
        except ValueError:
            pass

        deleted = store.delete(csv_item["attachment_id"], "owner-a")
        assert deleted["status"] == "deleted"

        print(json.dumps({
            "ok": True,
            "attachments_tested": len(manifest),
            "ownership_isolation": True,
            "types": ["txt", "csv", "docx", "xlsx", "jpg"],
        }))


if __name__ == "__main__":
    main()
