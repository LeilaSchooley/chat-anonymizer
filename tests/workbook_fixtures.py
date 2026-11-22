"""Minimal, entirely synthetic Office/OpenDocument files for import regression tests."""
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZipFile, ZIP_DEFLATED


def make_xlsx(path):
    path = Path(path)
    names = ['Orders', 'Other sheet']
    data = [
        [['record', 'order', 'email', 'amount', 'enabled'],
         ['synthetic-id', 1001, 'buyer@example.test', 14999, False],
         ['synthetic-id', 1001, 'buyer@example.test', 14999, True]],
        [['', 'record', 'email'], ['', 'other-id', 'other@example.test']],
    ]
    namespace = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    rel = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
    package = 'http://schemas.openxmlformats.org/package/2006/relationships'
    types = 'http://schemas.openxmlformats.org/package/2006/content-types'
    content_type = {
        '.xlsm': 'application/vnd.ms-excel.sheet.macroEnabled.main+xml',
        '.xltx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml',
        '.xltm': 'application/vnd.ms-excel.template.macroEnabled.main+xml',
    }.get(path.suffix, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml')
    with ZipFile(path, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', f'<Types xmlns="{types}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="{content_type}"/>' + ''.join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in (1, 2)) + '</Types>')
        archive.writestr('_rels/.rels', f'<Relationships xmlns="{package}"><Relationship Id="rId1" Type="{rel}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        archive.writestr('xl/workbook.xml', f'<workbook xmlns="{namespace}" xmlns:r="{rel}"><sheets>' + ''.join(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>' for i, name in enumerate(names, 1)) + '</sheets></workbook>')
        archive.writestr('xl/_rels/workbook.xml.rels', f'<Relationships xmlns="{package}">' + ''.join(f'<Relationship Id="rId{i}" Type="{rel}/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in (1, 2)) + '</Relationships>')
        for index, rows in enumerate(data, 1):
            elements = []
            for row_number, row in enumerate(rows, 1):
                cells = []
                for column, value in enumerate(row):
                    reference = f'{chr(65 + column)}{row_number}'
                    if isinstance(value, bool):
                        cell = f'<c r="{reference}" t="b"><v>{int(value)}</v></c>'
                    elif isinstance(value, (int, float)):
                        cell = f'<c r="{reference}"><v>{value}</v></c>'
                    else:
                        cell = f'<c r="{reference}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'
                    cells.append(cell)
                elements.append(f'<row r="{row_number}">' + ''.join(cells) + '</row>')
            archive.writestr(f'xl/worksheets/sheet{index}.xml', f'<worksheet xmlns="{namespace}"><sheetData>' + ''.join(elements) + '</sheetData></worksheet>')
    return path
