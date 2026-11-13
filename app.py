import json
import os
from datetime import datetime

import streamlit as st

import vault
import integrity   # teammate's module

st.set_page_config(page_title="DocVault", page_icon="🔒")

NOT_READY = ("integrity.py is not finished yet. Merge your teammate's work "
             "(see the notes) and try again.")


# ---------- Sidebar ----------
st.sidebar.markdown("## 🔒 DocVault")
page = st.sidebar.radio("Go to", ["Upload", "My Files", "Verify Vault"],
                        label_visibility="collapsed")
st.sidebar.caption("AES-256-GCM | scrypt")


# ---------- Helpers ----------
def short(h: str) -> str:
    """a91f3c...03 style display of a long hash."""
    return h if len(h) <= 10 else f"{h[:4]}...{h[-2:]}"


def logged_hashes() -> dict:
    """Latest logged hash of each file, read from the audit log."""
    path = os.path.join("logs", "audit_log.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            log = json.load(f)
    except ValueError:
        return {}
    hashes = {}
    for entry in log:
        if entry.get("action") == "UPLOAD":
            hashes[entry["file"]] = entry["file_hash"]
    return hashes


def run_verification():
    """Check the audit chain and every file, then show the results."""
    try:
        chain_ok, bad_entry = integrity.verify_log()
    except TypeError:
        st.warning(NOT_READY)
        return
    except Exception:
        chain_ok, bad_entry = False, "an unreadable entry"

    logged = logged_hashes()
    names = sorted(set(logged) | set(vault.list_files()))
    rows = []
    for name in names:
        path = os.path.join(vault.VAULT_DIR, name + ".enc")
        logged_hash = logged.get(name, "(not logged)")
        if not os.path.exists(path):
            rows.append((name, logged_hash, "(missing)", "DELETED", "listed in the log but missing from the vault folder"))
            continue
        ok, reason = integrity.verify_file(name)
        current = integrity.sha256_file(path)
        rows.append((name, logged_hash, current, "OK" if ok else "TAMPERED",
                     "" if ok else str(reason)))

    tampered = sum(1 for r in rows if r[3] == "TAMPERED")
    deleted = sum(1 for r in rows if r[3] == "DELETED")
    problems = tampered + deleted

    c1, c2, c3 = st.columns(3)
    c1.metric("Audit log chain", "OK" if chain_ok else "BROKEN")
    c2.metric("Files checked", len(rows))
    c3.metric("Problems found", problems)

    if not chain_ok:
        st.error(f"LOG TAMPERED: the audit chain is broken at {bad_entry}.")
    if problems:
        st.error(f"TAMPERED: {tampered} file(s) modified, {deleted} file(s) deleted. "
                 "Do not trust this vault.")
    elif chain_ok:
        st.success("All files verified. The vault is intact.")

    # Results table
    h1, h2, h3, h4 = st.columns([2, 2, 2, 1.5])
    h1.markdown("**File**"); h2.markdown("**Logged hash**")
    h3.markdown("**Current hash**"); h4.markdown("**Status**")
    colour = {"OK": "green", "TAMPERED": "red", "DELETED": "orange"}
    for name, lh, ch, status, reason in rows:
        a, b, c, d = st.columns([2, 2, 2, 1.5])
        a.write(name); b.code(short(lh)); c.code(short(ch))
        d.markdown(f":{colour[status]}[**{status}**]")
    for name, lh, ch, status, reason in rows:
        if reason:
            st.caption(f"{name}: {reason}")
    st.caption(f"Last checked: {datetime.now().strftime('%d-%m-%Y %H:%M')}")


# ---------- Page 1: Upload ----------
if page == "Upload":
    st.header("Upload a file to the vault")
    st.caption("Your file is encrypted with AES-256-GCM before it is saved.")
    uploaded = st.file_uploader("Choose a file")
    password = st.text_input("Password", type="password")
    st.caption("Use a strong password. It is never stored.")

    if st.button("Encrypt and Save", type="primary"):
        if uploaded is None or not password:
            st.warning("Choose a file and enter a password.")
        else:
            try:
                file_hash = vault.add_file(uploaded.name, uploaded.getvalue(), password)
                st.success("File encrypted and saved")
                st.code(f"SHA-256 logged: {uploaded.name}  {short(file_hash)}")
            except vault.VaultError as e:
                st.warning(str(e))
            except TypeError:
                st.warning(NOT_READY)


# ---------- Page 2: My Files ----------
elif page == "My Files":
    st.header("Files in the vault")
    st.caption("Select a file, enter its password, and download the decrypted copy.")
    files = vault.list_files()

    if not files:
        st.info("The vault is empty. Upload a file first.")
    else:
        name = st.selectbox("Select file", files)
        password = st.text_input("Password", type="password", key="download_pw")

        if st.button("Verify, Decrypt, Download", type="primary"):
            st.session_state.pop("download", None)
            try:
                data = vault.get_file(name, password)
                st.session_state["download"] = (name, data)
            except vault.TamperedError as e:
                st.error(str(e))
            except vault.WrongPasswordError as e:
                st.warning(str(e))
            except TypeError:
                st.warning(NOT_READY)

        saved = st.session_state.get("download")
        if saved and saved[0] == name:
            st.success("Integrity verified. Download ready.")
            st.caption("Audit chain OK | file hash matches | GCM tag valid")
            st.download_button(f"Download {name}", saved[1], file_name=name)


# ---------- Page 3: Verify Vault ----------
else:
    st.header("Vault integrity check")
    st.caption("Checks the audit log chain and every file against its logged hash.")
    if st.button("Run full verification", type="primary"):
        run_verification()