import tkinter as tk
from tkinter import messagebox
import smtplib
from email.message import EmailMessage
import os
import ctypes
import sys
import subprocess
import json
import locale


def on_mousewheel(event):
    if canvas.winfo_exists():
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


def fix_turkish_chars(text):
    replacements = {
        'Ý': 'İ', 'ý': 'ı',
        'Ð': 'Ğ', 'ð': 'ğ',
        'Þ': 'Ş', 'þ': 'ş'
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text

def create_turkish_safe_entry(master, width=30):
    var = tk.StringVar()

    def on_change(varname, index, mode):
        value = var.get()
        new_value = fix_turkish_chars(value)
        if value != new_value:
            var.set(new_value)

    var.trace_add("write", on_change)
    entry = tk.Entry(master, textvariable=var, width=width)
    return entry, var

def run_powershell_script(ps_script):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_script],
        capture_output=True,
        encoding="utf-8",
        errors="replace"
    )
    if result.returncode != 0:
        print("PowerShell komutu hata verdi:", result.stderr)
        return None
    return result.stdout

SMTP_SERVER = "smtp.barsan.com"
FROM_EMAIL = "cagrit@barsan.com"
CC_EMAIL = "taner.karakaya@barsan.com"


# --- Yeni kullanıcı maili içine NOT altına gömülecek görsel ---
USER_TEMPLATE_IMG = "//barsan.com/sistemdestek/Destek/Taner/images/user_creation.png"  # kendi dosya yolun


def convert_to_english_characters(text: str) -> str:
    tr_chars = 'çğıöşüÇĞİÖŞÜ'
    en_chars = 'cgiosuCGIOSU'
    return text.translate(str.maketrans(tr_chars, en_chars))

def turkish_lower(text):
    replacements = {
        'I': 'ı', 'İ': 'i',
        'Ş': 'ş', 'Ğ': 'ğ',
        'Ü': 'ü', 'Ö': 'ö', 'Ç': 'ç'
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.lower()

def is_null_or_whitespace(text):
    return text is None or text.strip() == ''

def get_distribution_groups():
    ps_script = '''
    $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new()
    Import-Module ActiveDirectory
    Get-ADGroup -Filter {GroupCategory -eq 'Distribution'} |
        Select-Object Name, DistinguishedName |
        ConvertTo-Json -Depth 2
    '''
    output = run_powershell_script(ps_script)
    if not output:
        return []

    try:
        groups = json.loads(output)
        if isinstance(groups, dict):
            groups = [groups]
        seen = set()
        clean_groups = []
        for g in groups:
            name = g.get('Name', '').strip()
            dn = g.get('DistinguishedName', '').strip()
            if name and name not in seen:
                clean_groups.append({'name': name, 'dn': dn})
                seen.add(name)
        return sorted(clean_groups, key=lambda x: x['name'].lower())
    except json.JSONDecodeError as e:
        print("JSON parse hatası:", e)
        print("Ham çıktı:", output)
        return []

def get_ous():
    parent_dn = "OU=BGL Bölgeler 2008,DC=barsan,DC=com"
    ps_script = f'''
    $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new()
    Import-Module ActiveDirectory
    Get-ADOrganizationalUnit -SearchBase "{parent_dn}" -Filter * | 
        Select-Object Name, DistinguishedName |
        ConvertTo-Json -Depth 3
    '''
    output = run_powershell_script(ps_script)
    if not output:
        return []

    def normalize(text):
        tr_chars = 'çğıöşüÇĞİÖŞÜ'
        en_chars = 'cgiosuCGIOSU'
        return text.translate(str.maketrans(tr_chars, en_chars)).lower()

    try:
        ous = json.loads(output)
        if isinstance(ous, dict):
            ous = [ous]
        return sorted(
            [{'name': ou['Name'], 'dn': ou['DistinguishedName']} for ou in ous],
            key=lambda ou: normalize(ou['name'])
        )
    except json.JSONDecodeError as e:
        print("JSON parse hatası:", e)
        print("Ham veri:", output)
        return []
def get_users_in_ou():
    parent_dn = "OU=BGL Bölgeler 2008,DC=barsan,DC=com"
    ps_script = f'''
    $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new()
    Import-Module ActiveDirectory
    Get-ADUser -SearchBase "{parent_dn}" -Filter * |
        Select-Object Name, UserPrincipalName |
        ConvertTo-Json -Depth 2
    '''
    output = run_powershell_script(ps_script)
    if not output:
        return []

    try:
        users = json.loads(output)
        if isinstance(users, dict):
            users = [users]
        return sorted(
            [{'name': u['Name'], 'email': u['UserPrincipalName']} for u in users if u.get('UserPrincipalName')],
            key=lambda x: x['name'].lower()
        )
    except Exception as e:
        print("Kullanıcı verisi okunamadı:", e)
        return []

       
    
import time  # Eğer dosyanın en üstüne eklemediysen mutlaka ekle

import time

def create_ad_user(user_info):
    try:
        first_name = user_info['first_name']
        last_name = user_info['last_name']
        description = user_info['description']
        office = user_info['office']
        pobox = user_info['pobox']
        ou_dn = user_info['ou']
        group_dns = user_info['groups']

        user_logon_name = convert_to_english_characters(f"{first_name.lower()}.{last_name.lower()}")
        global generated_password
        password = f"{convert_to_english_characters(first_name[0].lower())}20*{convert_to_english_characters(last_name[0].upper())}25!"
        generated_password = password


        company = "Barsan Global Lojistik A.S"
        display_name = f"{first_name} {last_name}"

        # 1. Kullanıcı oluşturma
        create_user_ps = f'''
        Import-Module ActiveDirectory
        $SecurePass = ConvertTo-SecureString "{password}" -AsPlainText -Force
        New-ADUser `
        -Name "{display_name}" `
        -GivenName "{first_name}" `
        -Surname "{last_name}" `
        -SamAccountName "{user_logon_name}" `
        -UserPrincipalName "{user_logon_name}@barsan.com" `
        -DisplayName "{display_name}" `
        -Path "{ou_dn}" `
        -AccountPassword $SecurePass `
        -Enabled $true `
        -ChangePasswordAtLogon $false `
        -Description "{description}" `
        -Office "{office}" `
        -POBox "{pobox}" `
        -Company "{company}"
        '''

        process1 = subprocess.run(["powershell", "-Command", create_user_ps], capture_output=True, text=True)
        if process1.returncode != 0:
            print("Kullanıcı oluşturma hatası:", process1.stderr)
            return None, None

        # 2. AD'nin tanıması için bekle
        time.sleep(2)

        # 3. Eklenmesi gereken gruplar
        all_groups = group_dns + [
            "CN=802Users,OU=802-1x,OU=BGL,DC=barsan,DC=com",
            "CN=BglTrmoo Users,OU=Security Groups,DC=barsan,DC=com",
            "CN=Duyuru,OU=Distribution Groups,DC=barsan,DC=com"
        ]

        for group_dn in all_groups:
            add_group_ps = f'''
            Import-Module ActiveDirectory
            Add-ADGroupMember -Identity "{group_dn}" -Members "{user_logon_name}"
            '''
            process2 = subprocess.run(["powershell", "-Command", add_group_ps], capture_output=True, text=True)
            if process2.returncode != 0:
                print(f"Grup ekleme hatası ({group_dn}):", process2.stderr)

        return user_logon_name, password

    except Exception as e:
        print(f"Genel Hata: {e}")
        return None, None  


def select_ou_popup(selected_ou_var):
    sub_ous = get_ous()
    ou_window = tk.Toplevel()
    ou_window.title("OU Seç")
    ou_window.geometry("350x300")
    ou_window.configure(bg="#0C2B47")  # Arka plan rengini burada ayarladık

    tk.Label(ou_window, bg="#0C2B47").pack(pady=5)  # Gri çizgi yerine arka planla aynı renk

    search_entry, search_var = create_turkish_safe_entry(ou_window, width=40)
    search_entry.pack()

    search_entry.insert(0, "Ara")
    search_entry.config(fg='grey')

    def on_entry_click(event):
        if search_entry.get() == "Ara":
            search_entry.delete(0, "end")
            search_entry.config(fg='black')

    def on_focusout(event):
        if search_entry.get() == "":
            search_entry.insert(0, "Ara")
            search_entry.config(fg='grey')

    search_entry.bind('<FocusIn>', on_entry_click)
    search_entry.bind('<FocusOut>', on_focusout)

    tk.Label(ou_window, text="Organizasyon Birimini Seçin:", bg="#0C2B47", fg="white").pack(pady=5)
    listbox = tk.Listbox(ou_window, height=10, width=40)
    listbox.pack(pady=5)

    # Başlangıçta tüm OU'ları listele
    for ou in sub_ous:
        listbox.insert(tk.END, ou['name'])

    # Arama kutusu güncellendiğinde çalışacak
    def refresh_listbox(*args):
        search_text = convert_to_english_characters(search_var.get().lower())
        listbox.delete(0, tk.END)
        for ou in sub_ous:
            if convert_to_english_characters(ou['name'].lower()).startswith(search_text):
                listbox.insert(tk.END, ou['name'])

    search_var.trace_add("write", refresh_listbox)

    def confirm_selection():
        selected = listbox.get(tk.ACTIVE)
        if selected:
            selected_ou_var.set(selected)
            ou_window.destroy()

    listbox.pack(pady=5)

    tk.Button(ou_window, text="Onayla", command=confirm_selection, bg="#28A745", fg="white").pack(pady=10)

def select_mail_recipient_popup(selected_email_var):
    users = get_users_in_ou()
    popup = tk.Toplevel()
    popup.title("Mail Alıcısı Seç")
    popup.geometry("400x500")
    popup.configure(bg="#0C2B47")

    tk.Label(popup, text="Kişi Ara:", bg="#0C2B47", fg="white").pack(pady=5)
    search_entry, search_var = create_turkish_safe_entry(popup, width=40)
    search_entry.pack()

    listbox = tk.Listbox(popup, height=20, width=50)
    listbox.pack(pady=10)

    for u in users:
        listbox.insert(tk.END, f"{u['name']} <{u['email']}>")

    def refresh():
        keyword = convert_to_english_characters(search_var.get().lower())
        listbox.delete(0, tk.END)
        for u in users:
            if keyword in convert_to_english_characters(u['name'].lower()):
                listbox.insert(tk.END, f"{u['name']} <{u['email']}>")

    search_var.trace_add("write", lambda *args: refresh())

    def confirm():
        selected = listbox.get(tk.ACTIVE)
        if selected and "<" in selected:
            email = selected.split("<")[1].split(">")[0]
            selected_email_var.set(email)
            popup.destroy()

    tk.Button(popup, text="Onayla", command=confirm,
              bg="#28A745", fg="white", width=15).pack(pady=10)


def send_user_creation_email(recipients, user_details, inline_image_path=None, attachment_path=None):
    import mimetypes, os
    from email.utils import make_msgid
    from email.message import EmailMessage

    try:
        with smtplib.SMTP(SMTP_SERVER, 25, timeout=10) as smtp:
            smtp.set_debuglevel(1)

            for recipient in recipients:
                msg = EmailMessage()
                msg['From']    = FROM_EMAIL
                msg['To']      = recipient
                if CC_EMAIL:
                    msg['Cc']  = CC_EMAIL
                msg['Subject'] = "Yeni Kullanıcı Taslak Ekranı"

                # 1) İçerik (plain + html)
                if isinstance(user_details, tuple) and len(user_details) == 2:
                    plain_text, html_tpl = user_details
                else:
                    plain_text, html_tpl = str(user_details), None

                msg.set_content(plain_text)

                img_cid = None
                if html_tpl:
                    html_to_send = html_tpl
                    if inline_image_path and os.path.isfile(inline_image_path):
                        img_cid = make_msgid()[1:-1]  # <> olmadan
                        html_to_send = html_tpl.replace("CID_IMAGE", f"cid:{img_cid}")
                    else:
                        # Görsel yoksa etiketi tamamen düşür
                        html_to_send = html_tpl.replace('src="CID_IMAGE"', 'src="" style="display:none;"')

                    msg.add_alternative(html_to_send, subtype='html')

                # 2) Inline görsel
                if img_cid:
                    mime, _ = mimetypes.guess_type(inline_image_path)
                    maintype, subtype = (mime or "image/png").split("/", 1)
                    with open(inline_image_path, "rb") as f:
                        msg.get_payload()[-1].add_related(
                            f.read(),
                            maintype=maintype,
                            subtype=subtype,
                            cid=img_cid
                        )

                # 3) Normal ek (opsiyonel)
                if attachment_path and os.path.isfile(attachment_path):
                    with open(attachment_path, 'rb') as f:
                        msg.add_attachment(
                            f.read(),
                            maintype='application',
                            subtype='octet-stream',
                            filename=os.path.basename(attachment_path)
                        )

                smtp.send_message(msg)
                print(f"E-posta gönderildi: {recipient}")
    except Exception as e:
        print(f"E-posta hatası: {e}")



def create_user_details_text(info, username, password):
    # -------- DÜZ METİN (fallback) --------
    text = f"""Merhaba,

Talep edilen kullanıcının bilgileri aşağıdaki gibidir:

Ünvan         : {info.get('description','')}
Mail Adresi   : {username}@barsan.com
Kullanıcı Adı : {username}
Kullanıcı Şifre: {password} (Şifreniz bilgi işlem tarafından geçici belirlenmiştir. İlk girişinizde gelen ekranda şifrenizi kendiniz belirleyebilirsiniz.)
Barsis Kodu   : {info.get('pobox','')}
Barsis Şifresi: {password}

NOT:
• MT Grup ayarlarınıza bağlı olacağınız grup talepleri için SÜREÇ GELİŞTİRME’ye; yetki talepleri için ITYAZILIM’a çağrı açmanız gereklidir.
• Barsan sistemine bgtrmoo.barsan.com adresinden bağlanabilirsiniz.
• Yazıcı eklemek için ekteki adımları izleyebilirsiniz.

Saygılarımla, iyi çalışmalar.
"""

    # -------- HTML (renkli etiketler + link + inline görsel) --------
    email = f"{username}@barsan.com"
    html = f"""\
<!doctype html>
<html>
  <body style="font-family:Segoe UI,Tahoma,Arial,sans-serif; font-size:14px; color:#222; line-height:1.45; margin:0; padding:16px;">
    <h3 style="text-align:center; color:#d91c1c; margin:0 0 12px;">YENİ KULLANICI TASLAK EKRANI</h3>

    <p style="margin:6px 0;">Merhaba,</p>
    <p style="margin:6px 0;">Talep edilen kullanıcının bilgileri aşağıdaki gibidir:</p>

    <table style="border-collapse:collapse; margin:8px 0 10px;">
      <tr><td style="padding:2px 8px 2px 0; color:#1a73e8; font-weight:600;">Ünvan</td><td>: {info.get('description','')}</td></tr>
      <tr><td style="padding:2px 8px 2px 0; color:#1a73e8; font-weight:600;">Mail Adresi</td><td>: <a href="mailto:{email}" style="color:#1a73e8; text-decoration:none;">{email}</a></td></tr>
      <tr><td style="padding:2px 8px 2px 0; color:#1a73e8; font-weight:600;">Kullanıcı Adı</td><td>: {username}</td></tr>
      <tr><td style="padding:2px 8px 2px 0; color:#1a73e8; font-weight:600;">Kullanıcı Şifre</td>
          <td>: {password} <span style="color:#b00000;">(Şifreniz bilgi işlem tarafından geçici belirlenmiştir. İlk girişinizde gelen ekranda şifrenizi kendiniz belirleyebilirsiniz.)</span></td></tr>
      <tr><td style="padding:2px 8px 2px 0; color:#1a73e8; font-weight:600;">Barsis Kodu</td><td>: {info.get('pobox','')}</td></tr>
      <tr><td style="padding:2px 8px 2px 0; color:#1a73e8; font-weight:600;">Barsis Şifresi</td><td>: {password}</td></tr>
    </table>

    <p style="margin:12px 0 6px;"><strong style="color:#d91c1c;">NOT:</strong></p>
    <ul style="margin:4px 0 10px 18px; padding:0;">
      <li><strong>MT Grup</strong> ayarlarınıza bağlı olacağınız grup talepleriniz için
          <strong style="color:#1a73e8;">SÜREÇ GELİŞTİRME</strong>, yetki talepleriniz için
          <strong style="color:#1a73e8;">ITYAZILIM</strong>'a çağrı açmanız gereklidir.</li>
      <li>Barsan sistemine <a href="https://bgtrmoo.barsan.com" style="color:#1a73e8;">bgtrmoo.barsan.com</a> adresinden bağlanabilirsiniz.</li>
      <li>Yazıcı eklemek için resimdeki adımları takip edebilirsiniz.</li>
    </ul>

    <div style="margin:8px 0 12px;">
      <img src="CID_IMAGE" alt="Yazıcı ekleme adımları" style="max-width:760px; border:1px solid #ddd; border-radius:6px;">
    </div>

    <p style="margin:8px 0;">Saygılarımla, iyi çalışmalar.</p>
  </body>
</html>
"""
    # DÖNÜŞ: (plain_text, html_template)
    return text, html


# 🧩 GRAFİKSEL ARAYÜZ
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk


# ---- mini geri ok butonu ----
def add_back_arrow_button(container, x, y, on_click, bg, fg):
    import tkinter as tk
    btn = tk.Button(
        container, text="←", command=on_click,
        bd=0, relief="flat",
        highlightthickness=0,
        highlightbackground=bg,
        highlightcolor=bg,
        bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
        font=("Segoe UI Symbol", 14, "bold"),
        cursor="hand2", takefocus=0, width=1, padx=4
    )
    btn.place(x=x, y=y)
    return btn



def user_creation_form(show_sidebar=True):

    import tkinter as tk
    from tkinter import messagebox
    from PIL import Image, ImageTk

    

    # ===== Tema (mock ile uyumlu) =====
    COL_BG    = "#E9EFF4"
    COL_TEXT  = "#1F2937"
    COL_LABEL = "#5B6B79"
    COL_LINE  = "#D3D9DE"
    COL_HEAD  = "#163B5A"
    COL_CARD  = "#F3F6F9"
    COL_WHITE = "#FFFFFF"




    def make_underlined_entry(master, width=35):
        wrap = tk.Frame(master, bg=COL_BG)

        entry, var = create_turkish_safe_entry(wrap, width=width)  # senin fonksiyonun

        # KUTUYU TAMAMEN GİZLE
        entry.configure(
            relief="flat",
            borderwidth=0,
            bd=0,
            highlightthickness=0,
            highlightbackground=COL_BG,   # Win/Mac kenarlığı kapat
            highlightcolor=COL_BG,
            bg=COL_BG,                    # sayfa ile aynı renk => kutu görünmez
            insertbackground=COL_TEXT,    # imleç rengi
            selectbackground="#DDE6EE",
            selectforeground=COL_TEXT
        )

        entry.pack(fill="x", padx=0, pady=(4, 2))
        tk.Frame(wrap, height=1, bg=COL_LINE).pack(fill="x")  # alt çizgi

        return wrap, entry, var


    def round_rect(canvas, x1, y1, x2, y2, r, **kwargs):
        pts = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r, x2,y2-r, x2,y2, x2-r,y2,
               x1+r,y2, x1,y2, x1,y2-r, x1,y1+r, x1,y1]
        return canvas.create_polygon(pts, smooth=True, **kwargs)

    # ===== Pencere =====
    root = tk.Tk()
    root.title("Kullanıcı Oluştur")
    root.geometry("880x600")
    root.resizable(False, False)
    root.configure(bg=COL_BG)


            # ← Menüye dön ok'u
    def _back_to_menu_from_user():
        try:
            root.destroy()          # bu pencereyi kapat
        finally:
            try:                    # ana menüyü aç (uygulamanda var)
                main_menu()
            except Exception:
                pass

    # Bu ekranda zemin açık renk olduğundan bg/fg böyle:
    add_back_arrow_button(root, 6, 10, _back_to_menu_from_user, bg=COL_BG, fg=COL_TEXT)

    # ===== Durum değişkenleri =====
    selected_groups = []
    selected_ou_var = tk.StringVar()
    selected_group_names_var = tk.StringVar()
    email_choice_var = tk.StringVar(value="Hayır")
    selected_email_recipient = tk.StringVar()

    # Sol form değişkenleri
    var_first_name = tk.StringVar()
    var_last_name  = tk.StringVar()
    var_description= tk.StringVar()
    var_office     = tk.StringVar()
    var_pobox      = tk.StringVar()

    # ===== Logo =====
    try:
        logo_path = "//barsan.com/sistemdestek/Destek/Taner/images/user_screen.png"
        img = Image.open(logo_path).resize((330, 80), Image.Resampling.LANCZOS)
        logo_photo = ImageTk.PhotoImage(img)
        tk.Label(root, image=logo_photo, bg=COL_BG).place(x=24, y=8)
        root._logo_ref = logo_photo
    except Exception as e:
        print("Logo yüklenemedi:", e)
        tk.Label(root, text="LOGO", bg=COL_BG, fg=COL_TEXT, font=("Arial", 14, "bold")).place(x=24, y=20)

    # ===== Sol Form =====
    form_frame = tk.Frame(root, bg=COL_BG)
    form_frame.place(x=24, y=110)
    form_frame.grid_columnconfigure(1, weight=1)  # çizgiler sağa uzasın

    def L(text): return tk.Label(form_frame, text=text, bg=COL_BG, fg=COL_TEXT, anchor="w", width=15)

    # Çizgi entry'ler
    L("İsim:").grid(row=0, column=0, pady=8, sticky="w")
    w_first, entry_first_name, var_first_name = make_underlined_entry(form_frame, width=38)
    w_first.grid(row=0, column=1, pady=8, sticky="we")

    L("Soy İsim:").grid(row=1, column=0, pady=8, sticky="w")
    w_last, entry_last_name, var_last_name = make_underlined_entry(form_frame, width=38)
    w_last.grid(row=1, column=1, pady=8, sticky="we")

    L("Açıklama / Ünvan:").grid(row=2, column=0, pady=8, sticky="w")
    w_desc, entry_description, var_description = make_underlined_entry(form_frame, width=38)
    w_desc.grid(row=2, column=1, pady=8, sticky="we")

    L("Lokasyon / Ofis:").grid(row=3, column=0, pady=8, sticky="w")
    w_off, entry_office, var_office = make_underlined_entry(form_frame, width=38)
    w_off.grid(row=3, column=1, pady=8, sticky="we")

    L("Barsis Kodu:").grid(row=4, column=0, pady=8, sticky="w")
    w_pobox, entry_pobox, var_pobox = make_underlined_entry(form_frame, width=38)
    w_pobox.grid(row=4, column=1, pady=8, sticky="we")

    # Bölgeler (buton + kutu)
    tk.Button(form_frame, text="Bölgeler", width=10, bg="#3E5261", fg="white",
              command=lambda: select_ou_popup(selected_ou_var)).grid(row=5, column=0, pady=8, sticky="w")
    tk.Entry(form_frame, textvariable=selected_ou_var, state="readonly", width=40)\
        .grid(row=5, column=1, pady=8, sticky="we")

    # Mail Grupları (buton + kutu)
    tk.Button(form_frame, text="Mail Grupları", width=10, bg="#3E5261", fg="white",
              command=lambda: select_groups_popup(selected_groups, selected_group_names_var))\
        .grid(row=6, column=0, pady=8, sticky="w")
    grp_wrap = tk.Frame(form_frame, bg=COL_BG)
    grp_wrap.grid(row=6, column=1, pady=8, sticky="we")
    sx = tk.Scrollbar(grp_wrap, orient="horizontal")
    sx.pack(side="bottom", fill="x")

    entry_with_scroll = tk.Entry(grp_wrap, textvariable=selected_group_names_var, state="readonly",
                                relief="sunken", xscrollcommand=sx.set, width=40)
    entry_with_scroll.pack(fill="x")

    sx.config(command=entry_with_scroll.xview)


    # E-posta tercihi
    tk.Label(form_frame, text="Kullanıcıya e-posta gönderilsin mi?", bg=COL_BG, fg=COL_TEXT)\
        .grid(row=7, column=0, columnspan=2, padx=(80,0), pady=(12,4), sticky="w")
    email_frame = tk.Frame(form_frame, bg=COL_BG)
    email_frame.grid(row=8, column=0, columnspan=2)  # sticky yok -> hücrede ortalanır
    tk.Radiobutton(email_frame, text="Evet",  variable=email_choice_var, value="Evet",  bg=COL_BG).pack(side="left", padx=10)
    tk.Radiobutton(email_frame, text="Hayır", variable=email_choice_var, value="Hayır", bg=COL_BG).pack(side="left", padx=10)

    def on_email_choice_change(*_):
        if email_choice_var.get() == "Evet":
            select_mail_recipient_popup(selected_email_recipient)
    email_choice_var.trace_add("write", on_email_choice_change)

    # İşlem butonları
    btns = tk.Frame(form_frame, bg=COL_BG); btns.grid(row=10, column=0, columnspan=2, pady=18)
    def on_submit():
        selected_ou_dn = next((o['dn'] for o in get_ous() if o['name'] == selected_ou_var.get()), None)
        info = {
            'first_name': var_first_name.get().strip(),
            'last_name' : var_last_name.get().strip(),
            'description':var_description.get().strip(),
            'office'    : var_office.get().strip(),
            'pobox'     : var_pobox.get().strip(),
            'ou'        : selected_ou_dn,
            'groups'    : selected_groups.copy()
        }
        if any(is_null_or_whitespace(v) for v in [info['first_name'], info['last_name'], info['ou']]):
            messagebox.showwarning("Eksik Bilgi", "Zorunlu alanları doldurunuz."); return
        logon_name, password = create_ad_user(info)
        if logon_name:
            detail = create_user_details_text(info, logon_name, password)
            if email_choice_var.get() == "Evet":
                recipient_email = selected_email_recipient.get()
                if not recipient_email:
                    messagebox.showwarning("Eksik Bilgi", "Lütfen e-posta alıcısını seçin."); return
                send_user_creation_email([recipient_email], detail, inline_image_path=USER_TEMPLATE_IMG)

            messagebox.showinfo("Başarılı", f"Kullanıcı '{logon_name}' oluşturuldu.")
            root.destroy()

    tk.Button(btns, text="Kullanıcı Oluştur", command=on_submit, bg="#28A745", fg="white", width=16)\
        .pack(side="left", padx=18)
    tk.Button(btns, text="İşlemi İptal Et",  command=root.destroy, bg="#D9534F", fg="white", width=16)\
        .pack(side="left", padx=18)
    

        # --- Kart sabitleri (tek yerden kontrol) ---
    CARD_W = 360      # kart genişliği
    CARD_H = 420      # kart yüksekliği
    HEADER_H = 98     # lacivert başlık yüksekliği
    RADIUS = 26
    PAD = 6
    INNER = 20        # kart iç boşluk
    SCROLLBAR_W = 12  # dikey scrollbar genişliği


        # ===== Sağ Kart =====
    # ===== Sağ Kart ===== 
    summary_host = tk.Frame(root, bg=COL_BG, width=360, height=520)
    summary_host.place(x=500, y=60)
    summary_host.pack_propagate(False)

    c = tk.Canvas(summary_host, bg=COL_BG, highlightthickness=0)
    c.pack(fill="both", expand=True)

        # gövde + başlık
    # --- gövde + başlık (düzenlenmiş) ---
    from tkinter import font as tkfont

    HEAD_X, HEAD_Y, HEAD_W, HEAD_H = 6, 6, 352, 78
    round_rect(c, 6, 6, 352, 410, 26, fill=COL_CARD, outline="")               # gövde
    round_rect(c, HEAD_X, HEAD_Y, HEAD_W, HEAD_H, 26, fill=COL_HEAD, outline="")  # başlık

    cx = HEAD_X + HEAD_W // 2

    ICON_SHIFT_RIGHT = 10   # px; sağa ne kadar gitsin istiyorsan artır/azalt
    icon_x = cx + ICON_SHIFT_RIGHT


    from tkinter import font as tkfont

    # 2) Eğer ID alamıyorsan sabit sınırlar (senin mock'ına göre)
    hx1, hy1, hx2, hy2 = 6, 6, 352, 78

    # ---- Yazı + Sembol stili ----
    EMOJI     = "ⓘ\uFE0E"   # düz (metin) sunum
    GAP       = 6           # yazı–ikon arası
    title_ft  = tkfont.Font(family="Arial", size=16, weight="bold")
    icon_ft   = tkfont.Font(family="Segoe UI Symbol", size=19)  # 20–24 arası oynat

    # Doğru
    title_id = c.create_text(26+5, 52, text="Kullanıcı Bilgisi",
                            fill="white", font=title_ft, anchor="w")

    # 2) Başlık bbox → merkez
    tx1, ty1, tx2, ty2 = c.bbox(title_id)
    title_cy = (ty1 + ty2) / 2

    # 3) İkonu başlığın SAĞINA, aynı dikey merkezde çiz
    icon_x  = tx2 + GAP
    icon_id = c.create_text(icon_x, title_cy, text=EMOJI,
                            fill="white", font=icon_ft, anchor="w")

    # 4) İkonun gerçek bbox merkezini başlık merkezine eşitle (garanti)
    _, iy1, _, iy2 = c.bbox(icon_id)
    c.move(icon_id, 0, title_cy - (iy1 + iy2) / 2)

    # 5) Grup (yazı+ikon) bbox'u
    gx1, gy1, gx2, gy2 = c.bbox(title_id, icon_id)

    # 6) Başlık alanı için İÇ kutu tanımla (sol/sağ padding veriyoruz)
    L_PAD, R_PAD = 16, 16   # eşit boşluk için iç kenarlar
    T_PAD, B_PAD = 0, 0     # istersen dikey padding de ekleyebilirsin

    inner_x1 = hx1 + L_PAD
    inner_x2 = hx2 - R_PAD
    inner_y1 = hy1 + T_PAD
    inner_y2 = hy2 - B_PAD

    # 7) Grubun genişliği/yüksekliği
    gw = gx2 - gx1
    gh = gy2 - gy1

    # 8) İstenen SOL ve ÜST koordinatı (iç kutu içinde tam ortalama)
    desired_left = inner_x1 + ( (inner_x2 - inner_x1) - gw ) / 2
    desired_top  = inner_y1 + ( (inner_y2 - inner_y1) - gh ) / 2

    dx = desired_left - gx1
    dy = desired_top  - gy1

    if dx or dy:
        c.move(title_id, dx, dy)
        c.move(icon_id, dx, dy)

    # İsteğe bağlı: optik denge için çok hafif sağa kaydırma
    CENTER_BIAS_X = +9    # sağa 4px; sola istersen negatif ver
    if CENTER_BIAS_X:
        c.move(title_id, CENTER_BIAS_X, 0)
        c.move(icon_id,  CENTER_BIAS_X, 0)









    # --- SCROLLABLE BODY (Canvas + Scrollbar) ---
    BODY_Y      = 90           # body’nin başladığı Y
    BODY_BOTTOM = 410            # kart gövdesinin alt sınırı
    AVAIL_W     = 328
    AVAIL_H     = BODY_BOTTOM - BODY_Y

    body_sc = tk.Canvas(summary_host, bg=COL_CARD, highlightthickness=0, bd=0)
    vbar    = tk.Scrollbar(summary_host, orient="vertical", command=body_sc.yview)
    body    = tk.Frame(body_sc, bg=COL_CARD)   # içerikleri buna eklemeye devam edeceğiz

    # inner frame'i canvas'a yerleştir → genişliği senkronize et
    body_win = body_sc.create_window((0, 0), window=body, anchor="nw", width=AVAIL_W - 12)
    body_sc.configure(yscrollcommand=vbar.set)

    def _sync_body_width(event=None):
        body_sc.itemconfigure(body_win, width=body_sc.winfo_width())
    body_sc.bind("<Configure>", _sync_body_width)

    def _on_body_config(_=None):
        body_sc.configure(scrollregion=body_sc.bbox("all"))
    body.bind("<Configure>", _on_body_config)

    # kart içinde konumlandır
    c.create_window(20, BODY_Y, window=body_sc, anchor="nw",
                    width=AVAIL_W - 12, height=AVAIL_H)  # -12: scrollbar payı
    c.create_window(20 + AVAIL_W, BODY_Y, window=vbar, anchor="ne",
                    height=AVAIL_H)

    # mouse wheel
    def _mw(e):
        if hasattr(e, "delta") and e.delta:
            body_sc.yview_scroll(int(-1 * (e.delta / 120)), "units")  # Win/Linux
        elif getattr(e, "num", None) == 4:
            body_sc.yview_scroll(-1, "units")                         # X11 up
        elif getattr(e, "num", None) == 5:
            body_sc.yview_scroll(1, "units")                          # X11 down

    body_sc.bind("<Enter>", lambda e: (
        body_sc.bind_all("<MouseWheel>", _mw),
        body_sc.bind_all("<Button-4>", _mw),
        body_sc.bind_all("<Button-5>", _mw)
    ))
    body_sc.bind("<Leave>", lambda e: (
        body_sc.unbind_all("<MouseWheel>"),
        body_sc.unbind_all("<Button-4>"),
        body_sc.unbind_all("<Button-5>")
    ))
    # --- SCROLLABLE BODY END ---

    def info_row(parent, title, top_pad=4):
        tk.Label(parent, text=title, bg=COL_CARD, fg=COL_LABEL,
                font=("Arial", 9, "bold")).pack(anchor="w", pady=(top_pad, 0))
        v = tk.Label(parent, text="-", bg=COL_CARD, fg=COL_TEXT, font=("Arial", 11))
        v.pack(anchor="w")
        return v

    label_kullanici = info_row(body, "Kullanıcı:", top_pad=0)
    label_email     = info_row(body, "E-posta:")
    label_password  = info_row(body, "Şifre:")
    label_ou        = info_row(body, "Organizasyon Birimi:")
    # label_title   = info_row(body, "Ünvan:")
    # label_office  = info_row(body, "Ofis:")
    label_pobox     = info_row(body, "Barsis Kodu:")

    # Mail Alıcısı satırı (boşluklar sıkı)
    tk.Label(body, text="Mail Alıcısı:", bg=COL_CARD, fg=COL_LABEL,
            font=("Arial", 9, "bold")).pack(anchor="w", pady=(4, 0))   # önce (6,0)

    label_selected_email = tk.Label(body, textvariable=selected_email_recipient,
                                    bg=COL_CARD, fg=COL_TEXT, font=("Arial", 11))
    label_selected_email.pack(anchor="w", pady=(0, 2))                   # önce (0,6)

    # Başlık: açık gri bant + ortalı metin (daha ince ve yukarıda)
    group_hdr = tk.Frame(body, bg="#DDE6EE", height=30)                  # önce 42
    group_hdr.pack(fill="x", pady=(1, 6))                                # önce (8, 8)
    group_hdr.pack_propagate(False)
    tk.Label(group_hdr, text="Seçilen Mail Grupları",
            bg="#DDE6EE", fg=COL_HEAD, font=("Arial", 11, "bold")).pack(expand=True)

    # Grupların listeleneceği alan (alt boşluğu da kısalttım)
    group_label_frame = tk.Frame(body, bg=COL_CARD)
    group_label_frame.pack(fill="both", expand=True, pady=(0, 0))        # önce (0,10)



    # ===== Dinamik özet =====
    def update_summary(*_):
        # TR düzelt -> TR lower -> ASCII -> boşlukları sil
        def clean(s: str) -> str:
            s = fix_turkish_chars(s or "")
            s = turkish_lower(s)
            s = convert_to_english_characters(s)
            return s.replace(" ", "")

        fn = clean(var_first_name.get())
        ln = clean(var_last_name.get())

        if fn and ln:
            username = f"{fn}.{ln}"
            email    = f"{username}@barsan.com"
            password = f"{fn[:1]}20*{ln[:1].upper()}25!"
        else:
            username = email = password = "-"

        label_kullanici.config(text=username)
        label_email.config(text=email)
        label_ou.config(text=selected_ou_var.get())
        label_password.config(text=password)
        # PO Box: ASCII'ye değil, sadece TR fix + trim yeterli
        label_pobox.config(text=(fix_turkish_chars((var_pobox.get() or "").strip()) or "-"))

        # Grup etiketlerini tazele
        for w in group_label_frame.winfo_children():
            w.destroy()
        for name in (selected_group_names_var.get() or "").split(", "):
            name = name.strip()
            if name:
                tk.Label(group_label_frame, text=name, bg=COL_CARD, fg=COL_TEXT, font=("Arial", 11)).pack(anchor="w")

        # Dinamik içerik sonrası scroll bölgesini yenile
        body_sc.update_idletasks()
        body_sc.configure(scrollregion=body_sc.bbox("all"))

    # Tetikleyiciler
    var_first_name.trace_add("write", update_summary)
    var_last_name.trace_add("write", update_summary)
    selected_ou_var.trace_add("write", update_summary)
    selected_group_names_var.trace_add("write", update_summary)
    var_pobox.trace_add("write", update_summary)

    # İlk açılışta özet boş kalmasın
   

    # --- YENİ: Yazarken anında güncelle (tek satır yeter) ---
    # 'win' senin bu formun penceresi (Toplevel/root). Adın farklıysa onu yaz.
    root.bind("<KeyRelease>", lambda e: update_summary())





    root.mainloop()






def select_groups_popup(selected_groups_var, selected_group_names_var):
    all_groups = get_distribution_groups()
    group_window = tk.Toplevel()
    group_window.title("Mail Grupları Seçimi")
    group_window.geometry("400x550")
    group_window.configure(bg="#0C2B47")  # Arka plan rengi eklendi

    

    tk.Label(group_window, text="Grup Ara:",fg="#FFFFFF", bg="#0C2B47").pack(pady=5)
    search_entry, search_var = create_turkish_safe_entry(group_window, width=40)
    search_entry.pack()

    outer_frame = tk.Frame(group_window, bd=1, relief="solid")
    outer_frame.pack(pady=5)

    canvas = tk.Canvas(outer_frame, width=330, height=220, background="white", bd=0, highlightthickness=0)
    scrollbar = tk.Scrollbar(outer_frame, orient="vertical", command=canvas.yview)
    checkbox_frame = tk.Frame(canvas, background="white")
    canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", on_mousewheel))
    canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))


    checkbox_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=checkbox_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    

    check_vars = []

    tk.Label(group_window, text="Eklenen Gruplar:", fg="#FFFFFF", bg="#0C2B47").pack(pady=5)
    listbox_selected = tk.Listbox(group_window, height=6, width=40)
    listbox_selected.pack(pady=5)

    def refresh_checkboxes():
        for widget in checkbox_frame.winfo_children():
            widget.destroy()
        check_vars.clear()
        keyword = convert_to_english_characters(search_entry.get().lower())

        for group in all_groups:
            if convert_to_english_characters(group['name'].lower()).startswith(keyword):
                var = tk.BooleanVar()
                cb = tk.Checkbutton(checkbox_frame, text=group['name'], variable=var,
                                    background="white", anchor="w",
                                    command=lambda g=group, v=var: on_check(g, v))
                cb.pack(fill='x', anchor='w')
                check_vars.append((var, group))

    def on_check(group, var):
        group_name = group['name']
        if var.get():
            if group_name not in listbox_selected.get(0, tk.END):
                listbox_selected.insert(tk.END, group_name)
        else:
            for i, item in enumerate(listbox_selected.get(0, tk.END)):
                if item == group_name:
                    listbox_selected.delete(i)
                    break

    def remove_selected():
        sel = listbox_selected.curselection()
        if not sel:
            return
        name = listbox_selected.get(sel[0])
        listbox_selected.delete(sel[0])
        for var, group in check_vars:
            if group['name'] == name:
                var.set(False)
                break

    def confirm_selection():
        names = listbox_selected.get(0, tk.END)
        selected_groups_var.clear()
        selected_groups_var.extend([g['dn'] for g in all_groups if g['name'] in names])
        selected_group_names_var.set(", ".join(names))
        group_window.destroy()

    search_entry.bind("<KeyRelease>", lambda e: refresh_checkboxes())
    refresh_checkboxes()

    # ⬇️ Butonlar bu kısma alınmalı
    button_frame = tk.Frame(group_window, bg="#0C2B47")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Seçimi Onayla", fg="white", bg="#28A745", command=confirm_selection, width=15).pack(side=tk.LEFT, padx=10)
    tk.Button(button_frame, text="Seçimi Kaldır", fg="white", bg="#D9534F", command=remove_selected, width=15).pack(side=tk.LEFT, padx=10)
    

# Gerekli diğer fonksiyonlar (select_groups_popup, select_ou_popup) yukarıda tanımlıysa olduğu gibi bırak.
def main_menu():
    import tkinter as tk
    from PIL import Image, ImageTk

    root = tk.Tk()
    root.title("Kullanıcı Paneli")
    root.resizable(width=False, height=False)  # Pencere sabit boyutta, büyütülemez
    
    root.geometry("300x400")
    
    root.configure(bg="white")

    sidebar = tk.Frame(root, width=300, bg="#0C2B47")
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    
    try:
        logo_path = "//barsan.com/sistemdestek/Destek/Taner/images/main_menu.png"
        logo_image = Image.open(logo_path)
        logo_image = logo_image.resize((200, 160), Image.Resampling.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(sidebar, image=logo_photo, bg="#0C2B47")
        logo_label.image = logo_photo
        logo_label.pack(pady=(20, 10))
    except:
        tk.Label(sidebar, text="LOGO", bg="#0C2B47", fg="white", font=("Arial", 20)).pack(pady=30)

    def open_user_creation():
        root.destroy()
        user_creation_form(show_sidebar=False)  # Sol panel gelmesin

    tk.Button(sidebar, text="Yeni Kullanıcı Oluştur", fg="white", bg="#1C3D5A",
              font=("Arial", 14, "bold"), command=open_user_creation).pack(pady=(40, 10), fill="x")

    tk.Label(sidebar, text="Sadece Yetkili\nKullanıcılar İçindir",
             fg="white", bg="#0C2B47", font=("Arial", 9), justify="center").pack(side="bottom", pady=20)
    
    # Gerekli diğer fonksiyonlar (select_groups_popup, select_ou_popup) yukarıda tanımlıysa olduğu gibi bırak.
import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk
from email.message import EmailMessage
import smtplib, os

# ===================== TEMA Sabitleri =====================
COL_BG    = "#F3F6F9"
COL_TEXT  = "#1F2937"
COL_LABEL = "#5B6B79"
COL_LINE  = "#D3D9DE"
COL_CARD  = "#FFFFFF"
COL_HEAD  = "#163B5A"
COL_OK    = "#28A745"
COL_NO    = "#D9534F"

# --- 700x570 için düzen ---
WIN_W, WIN_H = 800, 670       # PENCERE
L_MARGIN, R_MARGIN, GAP = 40, 20, 20
CARD_W, CARD_H = 260, 400
LEFT_W = WIN_W - L_MARGIN - R_MARGIN - GAP - CARD_W   # 360
TOP_Y  = 100                                           # üstten hizalama

# ===================== Yardımcılar =====================
def fix_turkish_chars(text: str) -> str:
    repl = {'Ý':'İ','ý':'ı','Ð':'Ğ','ð':'ğ','Þ':'Ş','þ':'ş'}
    for o,n in repl.items(): text = text.replace(o,n)
    return text

def create_turkish_safe_entry(master, **kwargs):
    var = tk.StringVar()
    def on_change(*_):
        v = var.get(); f = fix_turkish_chars(v)
        if v != f: var.set(f)
    var.trace_add("write", on_change)
    ent = tk.Entry(master, textvariable=var, **kwargs)
    return ent, var

def round_rect(canvas, x1, y1, x2, y2, r=16, **kw):
    pts = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r, x2,y2-r, x2,y2, x2-r,y2, x1+r,y2,
           x1,y2, x1,y2-r, x1,y1+r, x1,y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class PillButton(tk.Canvas):
    def __init__(self, master, text, bg, fg="white", padx=18, pady=10, radius=18,
                 font=("Segoe UI Semibold", 12), command=None):
        tk.Canvas.__init__(self, master, highlightthickness=0, bg=master["bg"])
        w = padx*2 + max(120, len(str(text))*7); h = pady*2+4
        self.configure(width=w, height=h)
        self.command, self.bgcol = command, bg
        self.body = round_rect(self, 0,0,w,h, r=radius, fill=bg, outline=bg)
        self.label = self.create_text(w//2, h//2, text=text, fill=fg, font=font)
        self.bind("<Button-1>", lambda e: self.command() if self.command else None)

# ===================== Sorun Bildir Penceresi (BAĞIMSIZ) =====================
# Bu pencereye özel e-posta ayarları

import os
import smtplib
import tkinter as tk
from tkinter import messagebox, filedialog
from email.message import EmailMessage
from PIL import Image, ImageTk

# ---- SMTP / Mail Ayarları ----
ISSUE_SMTP_HOST   = "smtp.barsan.com"
ISSUE_SMTP_PORT   = 25

# Alıcı sabit (hep cagrit@barsan.com)
ISSUE_RECIPIENTS  = ["cagrit@barsan.com"]     # PROD
# ISSUE_RECIPIENTS  = ["esra.sonmez@barsan.com"]  # TEST

# Logo yolu 
LOGO_PATH = "//barsan.com/sistemdestek/Destek/Taner/images/user_screen.png"

# (Opsiyonel) Geri ok görseli — varsa kullanılır; yoksa metin ok "←" gösterilir
BACK_ARROW_IMG = "//barsan.com/sistemdestek/Destek/Taner/images/back_arrow_24.png"  # İstersen yorum satırı yapabilirsin

# ---- Yardımcılar ----
def fix_turkish_chars(text: str) -> str:
    replacements = {
        'Ý': 'İ', 'ý': 'ı',
        'Ð': 'Ğ', 'ð': 'ğ',
        'Þ': 'Ş', 'þ': 'ş'
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text

class TurkishSafeText(tk.Text):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        # Tk komutunu yeniden adlandır ve proxy tanımla
        self._orig = self._w + "_orig"
        self.tk.call("rename", self._w, self._orig)
        self.tk.createcommand(self._w, self._proxy)

        # Yapıştırma kestirmeleri: hepsi sanitize tetikler
        self.bind("<<Paste>>", self._on_paste)
        self.bind("<Control-v>", self._on_paste)
        self.bind("<Control-V>", self._on_paste)
        self.bind("<Shift-Insert>", self._on_paste)

    def _proxy(self, cmd, *args):
        result = self.tk.call(self._orig, cmd, *args)
        if cmd in ("insert", "replace", "delete"):
            self._sanitize_all()
        return result

    def _sanitize_all(self):
        try:
            insert_idx = self.index("insert")
            content = self.get("1.0", "end-1c")
            fixed   = fix_turkish_chars(content)
            if content != fixed:
                self.delete("1.0", "end")
                self.insert("1.0", fixed)
                try:
                    self.mark_set("insert", insert_idx)
                except tk.TclError:
                    pass
        except tk.TclError:
            pass

    def _on_paste(self, e=None):
        self.after(1, self._sanitize_all)
        return None

def create_turkish_safe_text(master, **text_kwargs):
    return TurkishSafeText(master, **text_kwargs)

# Basit "pill" görünümlü buton (Canvas tabanlı değil; üstteki try/except bunu tolere ediyor)
class PillButton(tk.Button):
    def __init__(self, master=None, radius=18, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(relief="flat", bd=0, highlightthickness=0, cursor="hand2")

def send_issue_email_issue(fullname, user_email, subject, body_text, attachment_path=None):
    """
    Formdaki kullanıcıdan (From) sabit alıcı(lar)a (To) mail atar.
    Kimden: fullname + user_email
    Kime  : ISSUE_RECIPIENTS
    """
    try:
        sender_name = (fullname or "Bilinmiyor").strip()
        sender_mail = (user_email or "").strip()

        if not sender_mail:
            return False, "Gönderici e-posta zorunludur."

        with smtplib.SMTP(ISSUE_SMTP_HOST, ISSUE_SMTP_PORT, timeout=15) as smtp:
            msg = EmailMessage()
            msg["From"]     = f"{sender_name} <{sender_mail}>"
            msg["To"]       = ", ".join(ISSUE_RECIPIENTS)
            msg["Reply-To"] = f"{sender_name} <{sender_mail}>"
            msg["Subject"]  = f"[Sorun Bildirimi] {subject.strip() if subject and subject.strip() else '(konu yok)'}"

            msg.set_content(
                f"Gönderen : {sender_name} <{sender_mail}>\n"
                f"Konu     : {subject or '(konu yok)'}\n\n"
                f"Açıklama:\n{(body_text or '').strip()}\n"
            )

            if attachment_path and os.path.isfile(attachment_path):
                with open(attachment_path, "rb") as f:
                    msg.add_attachment(
                        f.read(),
                        maintype="application",
                        subtype="octet-stream",
                        filename=os.path.basename(attachment_path)
                    )

            smtp.send_message(msg, from_addr=sender_mail, to_addrs=ISSUE_RECIPIENTS)
        return True, None
    except Exception as e:
        return False, str(e)

# ---- mini geri ok (HALO YOK): Button yerine Label + opsiyonel görsel ----
def add_back_arrow_button(container, x, y, on_click, bg, fg, image_path=None, size=24, text_char="\u2190"):
    """
    image_path verilirse onu kullanır.
    Verilmezse global BACK_ARROW_IMG varsa dener.
    Hiçbiri yoksa metin ok (text_char, default '←') gösterir.
    Windows accent/focus halkası oluşmaması için Label kullanılır.
    """
    import os

    # Güvenli yol seçimi (NameError yok)
    path = image_path if image_path else globals().get("BACK_ARROW_IMG", None)

    # Varsayılan: metin ok
    lbl = tk.Label(
        container,
        text=text_char,                # ←
        bg=bg, fg=fg,
        font=("Segoe UI Symbol", 14, "bold"),
        cursor="hand2",
        bd=0, relief="flat",
        highlightthickness=0,
        takefocus=0,
        padx=4, pady=2                 # tıklanabilir alanı biraz genişlet
    )

    # PNG/JPG/ICO varsa kullan; yoksa metin oku bırak
    try:
        if path and os.path.isfile(path):
            img = Image.open(path).resize((size, size), Image.Resampling.LANCZOS)
            ph  = ImageTk.PhotoImage(img)
            lbl.configure(image=ph, text="")
            lbl._img = ph  # GC koruması
    except Exception:
        # Görsel okunamazsa sessizce metin ok ile devam
        pass

    lbl.place(x=x, y=y)

    # Tıklama olayı
    lbl.bind("<Button-1>", lambda e: on_click())

    # Her ihtimale karşı fokus gelirse anında konteynıra geri ver → halo olmaz
    lbl.bind("<FocusIn>", lambda e: container.focus_set())

    return lbl

def open_issue_report_window(parent):
    # ---- renkler ----
    COL_BG, COL_TEXT, COL_LABEL, COL_LINE = "#F3F6F9", "#1F2937", "#5B6B79", "#D3D9DE"
    COL_CARD, COL_HEAD, COL_OK, COL_NO    = "#FFFFFF", "#163B5A", "#28A745", "#D9534F"

    # --- Layout (700x570) ---
    WIN_W, WIN_H = 700, 570
    L_MARGIN, R_MARGIN, GAP = 40, 20, 20
    CARD_W, CARD_H = 260, 400
    LEFT_W = WIN_W - L_MARGIN - R_MARGIN - GAP - CARD_W
    BRAND_Y = 1
    TOP_Y   = 102

    win = tk.Toplevel(master=parent) if (parent and parent.winfo_exists()) else tk.Tk()


        # ← geri handler (MENÜYE DÖN)
    def _back_to_menu_from_issue():
        try:
            win.destroy()
        finally:
            try:
                if parent and parent.winfo_exists():
                    parent.deiconify(); parent.lift(); parent.focus_force()
                else:
                    main_menu()   # parent yoksa ana menüyü YENİDEN AÇ
            except Exception:
                main_menu()


    # (İsteğe bağlı) klavye kısayolları
    win.bind("<Escape>",   lambda e: _back_to_menu_from_issue())
    win.bind("<Alt-Left>", lambda e: _back_to_menu_from_issue())

    win.title("Sorun Bildir")
    win.geometry(f"{WIN_W}x{WIN_H}")
    win.resizable(False, False)
    win.configure(bg=COL_BG)

    def _round(canvas, x1,y1,x2,y2,r=12, **kw):
        pts=[x1+r,y1,x2-r,y1,x2,y1,x2,y1+r,x2,y2-r,x2,y2,x2-r,y2,x1+r,y2,x1,y2,x1,y2-r,x1,y1+r,x1,y1]
        return canvas.create_polygon(pts, smooth=True, **kw)

    # ── Logo + başlık ──
    MAX_LOGO_W = 250
    brand = tk.Canvas(win, bg=COL_BG, highlightthickness=0, width=350, height=56)
    brand.place(x=L_MARGIN-50, y=BRAND_Y)
    title_lbl = tk.Label(win, text="Sorun Bildir", bg=COL_BG, fg="#1C3D5A", font=("Arial", 13, "bold" ))

    def render_brand_and_title():
        brand.delete("all")
        for ch in brand.winfo_children(): ch.destroy()
        brand_h = 56
        if LOGO_PATH and os.path.isfile(LOGO_PATH):
            try:
                img = Image.open(LOGO_PATH)
                w,h = img.size
                w_percent = min(1.0, MAX_LOGO_W / float(w))
                h_size = int(h * w_percent)
                img = img.resize((int(w* w_percent), h_size), Image.Resampling.LANCZOS)
                ph = ImageTk.PhotoImage(img)
                brand_h = h_size + 2
                brand.configure(height=brand_h)
                logo_lbl = tk.Label(brand, image=ph, bg=COL_BG); logo_lbl.image = ph
                brand.create_window(0, 10, window=logo_lbl, anchor="nw")
            except Exception as e:
                print("Logo yüklenemedi:", e)
                brand_h = 56; brand.configure(height=brand_h)



        win.update_idletasks()
        title_y = BRAND_Y + brand.winfo_height() + 8
        title_lbl.place(x=L_MARGIN, y=title_y)
        title_lbl.tkraise()

    render_brand_and_title()

    # ← geri (Label tabanlı; HALO YOK) — image_path vermiyoruz: PNG yoksa otomatik "←"
    ok_btn = add_back_arrow_button(
        win, 6, 6, _back_to_menu_from_issue,
        bg=COL_BG, fg=COL_TEXT
    )
    ok_btn.lift()

    # Not: Önceden Button için ok_btn.configure(...) vardı; artık Label olduğu için YOK.


    # ---- Sol form ----
    left = tk.Frame(win, bg=COL_BG)
    win.update_idletasks()
    left_y = title_lbl.winfo_y() + title_lbl.winfo_height() + 12
    left.place(x=L_MARGIN, y=left_y, width=LEFT_W)

    def u_entry(lbl):
        row = tk.Frame(left, bg=COL_BG); row.pack(anchor="w", pady=0, fill="x")
        tk.Label(row, text=lbl, bg=COL_BG, fg=COL_LABEL, font=("Segoe UI",10)).pack(anchor="w")
        e,v = create_turkish_safe_entry(
            row, bd=0, relief="flat", bg=COL_BG, fg=COL_TEXT,
            insertbackground=COL_TEXT, font=("Segoe UI",11)
        )
        e.pack(anchor="w", fill="x", padx=(0,2))
        c = tk.Canvas(row, height=0, bg=COL_BG, highlightthickness=0); c.pack(fill="x", pady=(0,0))
        c.create_line(0,1,LEFT_W-40,1, fill=COL_LINE, width=2)
        return e,v

    e_first,v_first = u_entry("İsim:")
    e_last, v_last  = u_entry("Soyisim:")
    e_mail, v_mail  = u_entry("E-posta:")
    e_subj, v_subj  = u_entry("Konu:")

    tk.Label(left, text="Sorun Açıklaması:", bg=COL_BG, fg=COL_LABEL, font=("Segoe UI",10))\
        .pack(anchor="w", pady=(8,6))

    txt = create_turkish_safe_text(
        left, width=44, height=4, font=("Segoe UI",11),
        bd=0, relief="flat", highlightthickness=1,
        highlightbackground=COL_LINE, highlightcolor=COL_LINE,
        bg="white", fg=COL_TEXT, insertbackground=COL_TEXT
    )
    txt.pack(anchor="w", pady=(0,6))


    # Dosya ekle
    attach = {"path": None}
    def pick_file():
        p = filedialog.askopenfilename(
            title="Ekran görüntüsü seç",
            filetypes=[("Görseller","*.png *.jpg *.jpeg *.webp *.bmp *.gif"), ("Tüm dosyalar","*.*")]
        )
        if p:
            attach["path"] = p
            try:
                file_btn.itemconfig(file_btn.label, text="Eklendi: " + os.path.basename(p))
            except Exception:
                pass
            update_preview()

    file_btn = PillButton(
        left, text="Dosya Ekle", bg="#163B5A",
        fg="white", font=("Segoe UI Semibold", 10),  # font aynı
        padx=10, pady=3,                              # 6 → 3
        command=pick_file
    )
    file_btn.pack(anchor="w", pady=(0,10))            # 5 → 3


    # ---- Sağ kart ----
    right_x = L_MARGIN + LEFT_W + GAP
    right   = tk.Frame(win, bg=COL_BG); right.place(x=right_x, y=TOP_Y, width=CARD_W, height=CARD_H)
    card = tk.Canvas(right, width=CARD_W, height=CARD_H, bg=COL_BG, highlightthickness=0); card.pack(fill="both", expand=True)

    R, HEADER_H = 24, 64
    _round(card, 1, 1, CARD_W-1, CARD_H-1, r=R, fill=COL_CARD, outline=COL_CARD)
    _round(card, 1, 1, CARD_W-1, HEADER_H + R, r=R, fill=COL_HEAD, outline=COL_HEAD)
    card.create_rectangle(1, HEADER_H, CARD_W-1, HEADER_H + R, fill=COL_CARD, outline=COL_CARD)
    # Başlık alanı: (1,1) - (CARD_W-1, HEADER_H)
    hx1, hy1, hx2, hy2 = 1, 1, CARD_W-1, HEADER_H
    hx_c, hy_c = (hx1 + hx2) / 2, (hy1 + hy2) / 2

    # Ortalı başlık
    card.create_text(hx_c, hy_c, text="IT System Support", anchor="center",
                    fill="white", font=("Segoe UI Semibold", 13))



    def label_at(y, t):  card.create_text(16, y,     text=t, anchor="w", fill=COL_LABEL, font=("Segoe UI",10))
    def value_at(y, t):  return card.create_text(16, y+18, text=t, anchor="nw", fill=COL_TEXT, font=("Segoe UI",10), width=CARD_W-40)


    base = HEADER_H + 24
    label_at(base, "E-posta gönderilecek adres:")
    card_to  = value_at(base, ", ".join(ISSUE_RECIPIENTS))
    label_at(base+54, "Konu:");   card_sub = value_at(base+54,  "Kullanıcı bildirimi")
    # --- Detay: başlığı (aynı yer) ---
    label_at(base+108, "Detay:")

    # --- Scroll destekli Detay alanı ---
    DETAY_W = CARD_W - 32          # sağ/sol iç boşluk sonrası görünür genişlik
    DETAY_H = 80                   # görünür yükseklik (px) -> istersen 90/120 yap
    detay_wrap  = tk.Frame(card, bg=COL_CARD)
    detay_text  = tk.Text(
        detay_wrap, wrap="word", height=6,               # 6 satır görünür
        font=("Segoe UI", 10), bg="white", fg=COL_TEXT,
        bd=0, highlightthickness=1,
        highlightbackground=COL_LINE, highlightcolor=COL_LINE
    )
    detay_vbar  = tk.Scrollbar(detay_wrap, orient="vertical", command=detay_text.yview)
    detay_text.configure(yscrollcommand=detay_vbar.set)
    detay_text.pack(side="left", fill="both", expand=True)
    detay_vbar.pack(side="right", fill="y")

    # Kart canvas'ına bu alanı pencere olarak yerleştir
    card.create_window(16, base+126, window=detay_wrap, anchor="nw", width=DETAY_W, height=DETAY_H)

    # --- Ek: satırını Detay kutusunun ALTINA al ---
    EK_Y = base + 126 + DETAY_H + 12
    label_at(EK_Y, "Ek:")
    card_att = value_at(EK_Y, "Ekran görüntüsü (isteğe bağlı)")

    # (İsteğe bağlı) mouse wheel ile kaydırma daha rahat olsun
    def _mw_detay(e):
        if hasattr(e, "delta") and e.delta:
            detay_text.yview_scroll(int(-1*(e.delta/120)), "units")
    detay_text.bind("<Enter>", lambda e: detay_text.bind_all("<MouseWheel>", _mw_detay))
    detay_text.bind("<Leave>", lambda e: detay_text.unbind_all("<MouseWheel>"))


    # Önizleme penceresi
    def _show_preview():
        w = tk.Toplevel(win); w.title("Önizleme"); w.geometry("620x480"); w.configure(bg=COL_BG)
        tk.Label(w, text="E-posta Önizleme", bg=COL_BG, fg=COL_TEXT, font=("Segoe UI Semibold",14)).pack(pady=(12,6))
        box = tk.Text(w, wrap="word", font=("Consolas",10), bg="white", fg=COL_TEXT,
                      highlightthickness=1, highlightbackground=COL_LINE)
        box.pack(padx=14, pady=8, fill="both", expand=True)
        fullname=(v_first.get().strip()+" "+v_last.get().strip()).strip() or "Bilinmiyor"
        user_mail=v_mail.get().strip()
        shown_mail = user_mail if user_mail else "— (belirtilmedi)"
        attach_name=os.path.basename(attach["path"]) if attach.get("path") else "(yok)"
        box.insert("1.0",
f"""Kime      : {", ".join(ISSUE_RECIPIENTS)}
Kimden    : {fullname} <{shown_mail}>
Konu      : {v_subj.get().strip() or 'Kullanıcı bildirimi'}

Açıklama:
{txt.get('1.0','end').strip()}

Ek        : {attach_name}
""")
        box.config(state="disabled")

    # Sağ kart butonu
    # Sağ kart butonu — Gönder/İptal ile aynı boyut
    FIXED_BTN_WIDTH = globals().get("FIXED_BTN_WIDTH", 10)  # Gönder/İptal ile aynıysa dokunma

    prev_btn = PillButton(
        card, text="Önizlemeyi Gör",
        bg= "#163B5A", fg="white",
        font=("Segoe UI Semibold", 10),
        padx=10, pady=4,
        width=FIXED_BTN_WIDTH, height=1,
        command=_show_preview
    )
    card.create_window(CARD_W//2, CARD_H-18, window=prev_btn, anchor="center")  # 12 px aşağı



    # Canlı özet
    # Canlı özet
    # Canlı özet
    def update_preview(*_):
        # Ham değerleri al
        subj_raw = v_subj.get()
        body_raw = txt.get("1.0", "end-1c")  # sondaki \n'ı alma

        # Önce burada TR fix yap → yarış/gecikme biter
        subj = fix_turkish_chars((subj_raw or "").strip()) or "Kullanıcı bildirimi"
        body = fix_turkish_chars(body_raw).strip() or "Açıklamanız burada önizlenir."

        # Kartı yaz
        card.itemconfigure(card_to,  text=", ".join(ISSUE_RECIPIENTS))
        card.itemconfigure(card_sub, text=subj)
        detay_text.config(state="normal")
        detay_text.delete("1.0", "end")
        detay_text.insert("1.0", body)
        detay_text.config(state="disabled")

        card.itemconfigure(
            card_att,
            text=(os.path.basename(attach["path"]) if attach.get("path")
                else "Ekran görüntüsü (isteğe bağlı)")
        )

    # ---- Tetikleyiciler (fonksiyonun HEMEN ALTINDA olmalı) ----
    v_subj.trace_add("write", update_preview)
    txt.bind("<<Modified>>", lambda e: (txt.edit_modified(False), update_preview()))

    # Yazarken anında güncelle (gecikmeyi öldürür)
    e_subj.bind("<KeyRelease>", lambda e: update_preview())   # Konu entry
    txt.bind("<KeyRelease>",     lambda e: update_preview())  # Açıklama text
    win.bind("<KeyRelease>",     lambda e: update_preview())  # Pencere genelinde

    # İlk boyama
    update_preview()

        # Gönder
    def _do_send():
        fullname = (v_first.get().strip()+" "+v_last.get().strip()).strip()
        mail     = v_mail.get().strip()
        subject  = fix_turkish_chars(v_subj.get().strip())      # ← DEĞİŞTİ
        body     = fix_turkish_chars(txt.get("1.0","end"))      # ← DEĞİŞTİ

        if not fullname or not subject or not body.strip() or not mail:
            messagebox.showwarning("Eksik Bilgi","İsim, e-posta, konu ve açıklama zorunludur.")
            return

        ok, err = send_issue_email_issue(fullname, mail, subject, body, attach.get("path"))
    


        if ok:
            messagebox.showinfo("Gönderildi","İletiniz IT masasına gönderildi.")
            win.destroy()
        else:
            messagebox.showerror("Hata", f"E-posta gönderilemedi.\n{err or ''}")

    # Gönder / İptal — kompakt
    # Gönder / İptal — kompakt ve eşit genişlik
    FIXED_BTN_WIDTH = 11  # 9–12 arası deneyebilirsin; 11 genelde yeterli

    btn_row = tk.Frame(left, bg=COL_BG); btn_row.pack(anchor="w", pady=2)

    PillButton(
        btn_row, text="Gönder", bg=COL_OK, fg="white",
        font=("Segoe UI Semibold", 10),
        padx=10, pady=5,
        width=FIXED_BTN_WIDTH, height=1,
        command=_do_send
    ).pack(side="left", padx=(0,8))

    PillButton(
        btn_row, text="İptal Et", bg=COL_NO, fg="white",
        font=("Segoe UI Semibold", 10),
        padx=10, pady=5,
        width=FIXED_BTN_WIDTH, height=1,
        command=win.destroy
    ).pack(side="left", padx=(6,8))



# ===================== Menü Butonu =====================
def create_issue_menu_button(parent):
    return tk.Button(parent, text="Sorun Bildir", fg="white", bg="#1C3D5A",
                     font=("Arial", 10, "bold"),
                     command=lambda: open_issue_report_window(parent))

# ===================== MAIN MENU =====================
def main_menu():
    import tkinter as tk
    from PIL import Image, ImageTk

    # -------- Tema / stil sabitleri --------
    COL_BG      = "#0C2B47"   # panel arkası
    COL_BTN     = "#1E4F7B"   # buton normal
    COL_BTN_HV  = "#285E8C"   # hover
    COL_BTN_AC  = "#163B5A"   # basılı
    COL_TEXT    = "#FFFFFF"   # beyaz
    COL_MUTED   = "#B7C3CE"   # alt yazı
    COL_DIV     = "#1A3A58"   # ince ayraç

    W, H = 320, 460  # pencere

    root = tk.Tk()
    root.title("Kullanıcı Paneli")
    root.resizable(False, False)
    root.configure(bg=COL_BG)

    # ekran ortalama
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    x = int((sw - W) / 2); y = int((sh - H) / 2.2)
    root.geometry(f"{W}x{H}+{x}+{y}")

    # ---- Sol/tek panel ----
    sidebar = tk.Frame(root, width=W, height=H, bg=COL_BG)
    sidebar.pack(fill="both", expand=True)
    sidebar.pack_propagate(False)

    # ---- Logo ----
    def load_logo():
        try:
            logo_path = "//barsan.com/sistemdestek/Destek/Taner/images/main_menu.png"
            logo_image = Image.open(logo_path)
            logo_image = logo_image.resize((240, 180), Image.Resampling.LANCZOS)  # Boyutu büyüttük
            logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = tk.Label(sidebar, image=logo_photo, bg="#0C2B47")
            logo_label.image = logo_photo
            logo_label.pack(pady=(10, 4))  # Daha yakın yerleşim
        except:
            tk.Label(sidebar, text="LOGO", bg="#0C2B47", fg="white", font=("Arial", 20)).pack(pady=(12, 4))


    logo_photo = load_logo()
    if logo_photo:
        tk.Label(sidebar, image=logo_photo, bg=COL_BG).pack(pady=(22, 8))
# else kısmını tamamen kaldırıyoruz ki yazı çıkmasın

    # İnce ayraç çizgisi
    tk.Frame(sidebar, bg=COL_DIV, height=1).pack(fill="x", padx=22, pady=(2, 18))

    # ---- Reusable buton üretici (hover/focus dâhil) ----
    def make_menu_button(parent, text, command):
        # Düz buton
        wrap = tk.Frame(parent, bg=COL_BG)
        wrap.pack(fill="x", padx=20, pady=8)

        btn = tk.Label(
            wrap, text=text, fg=COL_TEXT, bg=COL_BTN,
            font=("Segoe UI Semibold", 13),
            padx=18, pady=12, anchor="center", cursor="hand2"
        )
        btn.pack(fill="x")

        def on_enter(e): btn.configure(bg=COL_BTN_HV)
        def on_leave(e): btn.configure(bg=COL_BTN)
        def on_press(e): btn.configure(bg=COL_BTN_AC)
        def on_release(e):
            btn.configure(bg=COL_BTN_HV)
            command()

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<ButtonPress-1>", on_press)
        btn.bind("<ButtonRelease-1>", on_release)
        btn.bind("<Return>", lambda e: command())
        btn.bind("<space>",  lambda e: command())
        btn.configure(highlightthickness=0)

        return btn



    # ---- Buton eylemleri ----
    def open_user_creation():
        root.destroy()
        # sol panel istemiyorsun: show_sidebar=False
        user_creation_form(show_sidebar=False)

    def open_issue():
        root.destroy()                     # ANA MENÜYÜ KAPAT
        open_issue_report_window(None)     # Sorun Bildir penceresini bağımsız aç


    # ---- Butonlar ----
    make_menu_button(sidebar, "Yeni Kullanıcı Oluştur", open_user_creation)
    make_menu_button(sidebar, "Sorun Bildir",          open_issue)

    # Alt yazı (footer)
    tk.Frame(sidebar, bg=COL_DIV, height=1).pack(fill="x", padx=22, pady=(18, 12))
    tk.Label(
        sidebar, text="Barsan IT System Support",
        fg=COL_MUTED, bg=COL_BG, font=("Segoe UI", 10)
    ).pack(side="bottom", pady=14)

    root.mainloop()









if __name__ == '__main__':
      main_menu()
