# xwiki
template nuclei untuk menemukan kerentanan RCE dan LFI pada Xwiki
Template Nuclei ini dirancang untuk melakukan validasi keamanan secara aman (non-destruktif) terhadap endpoint /xwiki/bin/get/Main/SolrSearch pada aplikasi XWiki.

Template ini tidak mengandung payload RCE, command injection, atau eksploitasi aktif. Fokus utama:

    ✅ Deteksi reflection payload (termasuk unik marker)

    ✅ Validasi escape karakter (XSS reflection detection)

    ✅ Fingerprinting versi XWiki & komponen terkait

    ✅ Info leakage pasif (path internal, OS fingerprint, file sensitif)

    ✅ Baseline comparison untuk analisis manual lanjutan

    ⚠️ Catatan: Template ini aman digunakan untuk scanning bug bounty / penetration testing dengan izin resmi. Tidak ada eksekusi perintah sistem.

🧪 Test Case Yang Dilakukan
No	Metode	Parameter text	Tujuan
1	GET	baselinecheck123	Baseline & ekstraksi versi XWiki
2	GET	}}}{{13371337}} (URL encoded)	Deteksi unik marker reflection
3	GET	"> <testXSS> (URL encoded)	Validasi escape karakter
4	GET	<testXSS> (URL encoded)	Deteksi raw HTML reflection
5	GET	linux	Info leakage pasif (OS, path, UID)
🎯 Indikator Kerentanan

Template ini akan mendeteksi potential vulnerability / misconfiguration jika ditemukan:
🔍 Reflection Payload

    Marker 13371337 muncul di <title> atau <description> RSS

    String <testXSS> muncul mentah (tidak di-escape) di body response

    Karakter "> <testXSS> tidak berhasil di-escape menjadi entitas HTML

📄 Info Leakage Pasif

    Path internal seperti /etc/passwd, /home/, /var/lib/xwiki

    OS fingerprint: Linux, Ubuntu, Debian, CentOS

    Network indicators: LISTEN, tcp, 0.0.0.0

    Command output remnant: uid=, gid=, groups=

🧬 Version Fingerprinting

    Versi XWiki yang muncul dalam response (leak dari konfigurasi)

    Versi library frontend (jQuery, underscore, Semantic UI)

    Versi plugin / komponen lain yang tidak seharusnya terekspos

📦 Cara Penggunaan
1. Simpan template

Simpan file sebagai:
bash

xwiki-solrsearch-advanced-validation-safe.yaml

2. Jalankan dengan Nuclei
bash

nuclei -t xwiki-solrsearch-advanced-validation-safe.yaml -u https://target.com

3. Contoh output
yaml

[xwiki-solrsearch-advanced-validation-safe:version] [http] [medium] 
https://target.com/xwiki/bin/get/Main/SolrSearch?media=rss&text=baselinecheck123
["version=8.18.4.0","xwiki-form-token","/etc/passwd","Linux"]

[xwiki-solrsearch-advanced-validation-safe:raw-reflection] [http] [medium] 
https://target.com/xwiki/bin/get/Main/SolrSearch?media=rss&text=%3CtestXSS%3E
["<testXSS>"]

🧠 Konteks Kerentanan (CVE-2025-24893)

Template ini terinspirasi dari CVE-2025-24893 – kerentanan Unauthenticated RCE pada XWiki melalui endpoint SolrSearch dengan skor CVSS 9.8 (Critical).

Meskipun template ini hanya melakukan deteksi pasif, temuan berikut mengindikasikan server berpotensi rentan terhadap eksploitasi RCE/LFI:
Indikator	Arti
Unik marker 13371337 tereksekusi / terekam di response	Kemungkinan server tidak memfilter makro → RCE
Raw HTML <testXSS> tidak di-escape	Konfirmasi kurangnya sanitasi input
Leak path /etc/passwd atau uid=	Info disclosure parah → bisa lanjut ke LFI
Leak versi XWiki kuno (di bawah 15.10.11 / 16.4.1)	Kerentanan diketahui belum di-patch

    🔗 Referensi resmi CVE: CVE-2025-24893

🛡️ Remediasi (Jika Ditemukan Rentan)

Jika template ini menghasilkan positive match (terutama pada marker 13371337 atau raw reflection):

    Segera upgrade XWiki ke versi:

        ≥ 15.10.11

        ≥ 16.4.1

        Atau versi terbaru

    Nonaktifkan endpoint SolrSearch jika tidak dibutuhkan secara publik

    Terapkan WAF rule untuk memfilter payload {{groovy}}, {{async}}, dan marker aneh

    Audit akses log – cek apakah server sudah pernah terkena eksploitasi RCE

📁 Struktur Template (Ringkasan)
yaml

id: xwiki-solrsearch-advanced-validation-safe
info:
  name: XWiki SolrSearch Advanced Reflection & Info Leakage Detection
  severity: medium
  tags: xwiki,reflection,infoleak,misconfig,safe

http:
  - method: GET
    path: /xwiki/bin/get/Main/SolrSearch?media=rss&text=baselinecheck123
    extractors: [version, content-type]

  - method: GET
    path: ...&text=%7D%7D%7D%7B%7B13371337%7D%7D
    matchers: [word: 13371337]

  - method: GET
    path: ...&text=%22%3E%3CtestXSS%3E
    matchers: [regex: &lt;testXSS&gt;]

  - method: GET
    path: ...&text=%3CtestXSS%3E
    matchers: [word: <testXSS>]

  - method: GET
    path: ...&text=linux
    matchers: [word: Linux, /etc/passwd, uid=...]

⚠️ Disclaimer

    Template ini dibuat untuk tujuan pengujian keamanan legal dan etis (bug bounty, authorized pentest, CTF).
    Penulis tidak bertanggung jawab atas penyalahgunaan di luar ketentuan hukum yang berlaku.

📎 Referensi

    XWiki Official Documentation

    CVE-2025-24893 Detail

    Nuclei Template Guide
