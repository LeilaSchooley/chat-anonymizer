from src.gui import main

if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        stage = "imports"
        try:
            import tkinter as tk
            from src.gui import App, create_root
            from src.json_redactor import redact_json
            from src.anonymizer import ChatAnonymizer
            from src.credentials import CredentialEngine, CredentialPolicy, CustomPattern
            import time
            import json
            stage = "GUI JSON redaction"
            root = create_root()
            root.withdraw()
            app = App(root)
            assert root.TkdndVersion and app.input.dnd_bind('<<Drop>>')
            app.input.insert('1.0', '{"twocaptcha_apikey":"short","count":2}')
            app.redact()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not app.status.get().startswith("Done:"):
                root.update()
                time.sleep(0.02)
            assert json.loads(app.output.get('1.0', 'end-1c')) == {"twocaptcha_apikey":"[REDACTED]","count":2}
            stage = "GUI five-file drop"
            from tempfile import TemporaryDirectory
            from pathlib import Path
            from types import SimpleNamespace
            with TemporaryDirectory(prefix='anonymizer-test-') as directory:
                paths = []
                for index in range(5):
                    path = Path(directory) / f'input with spaces {index}.json'
                    path.write_text(json.dumps({"token":"synthetic", "index":index}))
                    paths.append(str(path))
                app.input.delete('1.0', 'end')
                payload = root.tk.call('format', '%s', tuple(paths))
                assert app.drop_files(SimpleNamespace(data=payload)) == 'copy'
                app.redact()
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not app.status.get().startswith("Done:"):
                    root.update()
                    time.sleep(.02)
                assert json.loads(app.output.get('1.0','end-1c')) == [{'token':'[REDACTED]', 'index':index} for index in range(5)]
                assert 'synthetic' not in app.output.get('1.0','end-1c')
            stage = "GUI redaction category settings"
            assert all(variable.get() for variable in app.categories.values())
            app.categories['USERNAME'].set(False)
            app.input.delete('1.0', 'end')
            app.input.insert('1.0', '{"username":"alice","password":"synthetic","enabled":false}')
            app.redact()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not app.status.get().startswith("Done:"):
                root.update()
                time.sleep(.02)
            assert json.loads(app.output.get('1.0','end-1c')) == {'username':'alice','password':'[REDACTED]','enabled':False}
            app.restore_categories()
            root.destroy()
            stage = "JSON adapter"
            assert redact_json('{"token":"fake","count":2}', ["token"])[0] == '{"token":"[REDACTED]","count":2}'
            assert redact_json('{"twocaptcha_apikey":"fake","count":2}', [], auto_sensitive=True)[0] == '{"twocaptcha_apikey":"[REDACTED]","count":2}'
            assert redact_json('{"preserve_cookies":false,"use_premade_cookies":true,"token":"fake"}', [], auto_sensitive=True)[0] == '{"preserve_cookies":false,"use_premade_cookies":true,"token":"[REDACTED]"}'
            stage = "proxy policy"
            from src.json_redactor import redact_json_result
            proxy = '{"proxy":"socks5://alice:synthetic@192.0.2.59:1080","enabled":false}'
            assert json.loads(redact_json_result(proxy).text)['proxy'] == 'socks5://[REDACTED]:[REDACTED]@192.0.2.59:1080'
            strict = CredentialEngine(CredentialPolicy(proxy_mode='strict'))
            assert '192.0.2.59' not in redact_json_result(proxy, engine=strict).text
            stage = "custom-pattern runtime"
            engine = CredentialEngine(CredentialPolicy(custom_patterns=(CustomPattern('org', r'ORG-[A-Z]{8}'),)))
            assert engine.apply_text('ORG-ABCDEFGH', engine.detect_text('ORG-ABCDEFGH')).text == '[REDACTED]'
            stage = "chat model and credentials"
            assert "synthetic-key" not in ChatAnonymizer().anonymize("twocaptcha_apikey: synthetic-key").text
            assert "synthetic@example.com" not in ChatAnonymizer().anonymize("Email synthetic@example.com").text
        except Exception:
            if len(sys.argv) > 2:
                from pathlib import Path
                Path(sys.argv[2]).write_text(f"Executable self-test failed at: {stage}. Input omitted.\n", encoding="utf-8")
            sys.exit(1)
    else:
        main()
