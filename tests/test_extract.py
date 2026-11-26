from __future__ import annotations

import unittest

from shotguard.extract import extract_media_urls, is_allowed_url


class TestExtract(unittest.TestCase):
    def test_extract_media_urls_order_and_dedupe(self) -> None:
        md = """
Here is a screenshot:
![first](https://github.com/user-attachments/assets/11111111-2222-3333-4444-555555555555)
And an HTML img:
<img width="400" src="https://user-images.githubusercontent.com/1234/abcd.png" alt="img">
A bare attachment link:
https://github.com/user-attachments/assets/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
And a video tag:
<video src='https://github.com/user-attachments/assets/99999999-8888-7777-6666-555555555555'></video>
Duplicate of first:
![dup](https://github.com/user-attachments/assets/11111111-2222-3333-4444-555555555555)
"""
        urls = extract_media_urls(md)
        self.assertEqual(
            urls,
            [
                "https://github.com/user-attachments/assets/11111111-2222-3333-4444-555555555555",
                "https://user-images.githubusercontent.com/1234/abcd.png",
                "https://github.com/user-attachments/assets/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "https://github.com/user-attachments/assets/99999999-8888-7777-6666-555555555555",
            ],
        )

    def test_is_allowed_url_ssrf_and_hosts(self) -> None:
        allowed_github = [
            "https://github.com/user-attachments/assets/11111111-2222-3333-4444-555555555555",
            "https://user-images.githubusercontent.com/1/2.png",
            "https://raw.githubusercontent.com/org/repo/main/a.png",
            "https://private-user-images.githubusercontent.com/1/2.png",
            "https://objects.githubusercontent.com/github-production-user-asset/a.png",
        ]
        for url in allowed_github:
            self.assertTrue(is_allowed_url(url), f"Expected allowed: {url}")

        blocked_always = [
            "http://github.com/user-attachments/assets/abc",
            "file:///etc/passwd",
            "https://localhost/a.png",
            "https://sub.localhost/a.png",
            "https://printer.local/a.png",
            "https://metadata.internal/a.png",
            "https://127.0.0.1/a.png",
            "https://10.0.0.1/a.png",
            "https://172.16.0.1/a.png",
            "https://192.168.1.1/a.png",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/a.png",
        ]
        for url in blocked_always:
            self.assertFalse(is_allowed_url(url, allow_any_host=False), url)
            self.assertFalse(is_allowed_url(url, allow_any_host=True), url)

        third_party = "https://cdn.example.com/shot.png"
        self.assertFalse(is_allowed_url(third_party, allow_any_host=False))
        self.assertTrue(is_allowed_url(third_party, allow_any_host=True))


if __name__ == "__main__":
    unittest.main()
