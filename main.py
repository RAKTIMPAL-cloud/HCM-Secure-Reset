import streamlit as st
import requests
import pandas as pd
import base64
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
import string
import secrets

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM: User & Role Creator", layout="wide")
st.title("👤 Oracle HCM: Bulk User & Role Management")

# --- Logic Functions ---

def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!#$%"
    pwd = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
           secrets.choice(string.digits), secrets.choice("!#$%")]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def fetch_guids_via_soap(env_url, admin_user, admin_pwd, usernames, roles):
    full_url = env_url.rstrip("/") + "/xmlpserver/services/ExternalReportWSSService"
    report_path = "/Custom/Human Capital Management/PASSWORD/User_Role_GUID_Report.xdo"
    
    user_str = ",".join(filter(None, set(usernames)))
    role_str = ",".join(filter(None, set(roles)))

    soap_request = f"""
    <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:pub="http://xmlns.oracle.com/oxp/service/PublicReportService">
       <soap:Body>
          <pub:runReport>
             <pub:reportRequest>
                <pub:attributeFormat>csv</pub:attributeFormat>
                <pub:reportAbsolutePath>{report_path}</pub:reportAbsolutePath>
                <pub:parameterNameValues>
                    <pub:item><pub:name>p_usernames</pub:name><pub:values><pub:item>{user_str}</pub:item></pub:values></pub:item>
                    <pub:item><pub:name>p_roles</pub:name><pub:values><pub:item>{role_str}</pub:item></pub:values></pub:item>
                </pub:parameterNameValues>
             </pub:reportRequest>
          </pub:runReport>
       </soap:Body>
    </soap:Envelope>"""
    
    auth = base64.b64encode(f"{admin_user}:{admin_pwd}".encode()).decode()
    headers = {"Content-Type": "application/soap+xml; charset=utf-8", "Authorization": f"Basic {auth}"}

    try:
        res = requests.post(full_url, data=soap_request, headers=headers)
        root = ET.fromstring(res.content)
        ns = {'ns': 'http://xmlns.oracle.com/oxp/service/PublicReportService'}
        report_bytes = root.find('.//ns:reportBytes', ns)
        if report_bytes is not None and report_bytes.text:
            return base64.b64decode(report_bytes.text).decode("utf-8")
        return None
    except Exception:
        return None

def execute_scim_bulk(env_url, admin_user, admin_pwd, operations):
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    payload = {"schemas": ["urn:scim:schemas:core:2.0:BulkRequest"], "failOnErrors": 0, "Operations": operations}
    return requests.post(scim_url, json=payload, auth=(admin_user, admin_pwd))

# --- UI Layout ---
col1, col2 = st.columns(2)
with col1:
    st.subheader("🌐 Connection")
    env_url = st.text_input("URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data")
    template_df = pd.DataFrame(columns=['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL', 'ROLE TO BE ASSIGNED'])
    tmp_buff = BytesIO()
    with pd.ExcelWriter(tmp_buff, engine='xlsxwriter') as writer:
        template_df.to_excel(writer, index=False)
    st.download_button("📥 Template", tmp_buff.getvalue(), "User_Role_Template.xlsx")
    uploaded_file = st.file_uploader("Upload Excel", type=["xlsx"])

# --- Execution Logic ---
if st.button("🚀 Run Process"):
    if not (username and password and uploaded_file):
        st.warning("Please complete all inputs.")
    else:
        df = pd.read_excel(uploaded_file)
        df.columns = [c.strip().upper() for c in df.columns]
        common_pwd = generate_secure_password()
        
        # 1. PHASE 1: CREATE USERS
        unique_users = df.drop_duplicates(subset=['USER NAME'])
        user_ops = []
        for _, row in unique_users.iterrows():
            user_ops.append({
                "method": "POST", "path": "/Users", "bulkId": str(row['USER NAME']),
                "data": {
                    "schemas": ["urn:scim:schemas:core:2.0:User"],
                    "userName": str(row['USER NAME']),
                    "name": {"familyName": str(row['LAST NAME']), "givenName": str(row['FIRST NAME'])},
                    "emails": [{"primary": True, "value": str(row['WORK EMAIL']), "type": "W"}],
                    "active": True, "password": common_pwd
                }
            })

        user_status_map = {}
        with st.spinner("⏳ Creating Users..."):
            res_u = execute_scim_bulk(env_url, username, password, user_ops)
            if res_u.status_code in [200, 201]:
                for op in res_u.json().get("Operations", []):
                    code = str(op.get("status", {}).get("code", ""))
                    user_status_map[op.get("bulkId")] = "CREATED" if code == "201" else "EXISTS" if code == "409" else "FAILED"

        # 2. PHASE 2: RESOLVE GUIDs
        with st.spinner("⏳ Resolving GUIDs..."):
            csv_data = fetch_guids_via_soap(env_url, username, password, df['USER NAME'].tolist(), df['ROLE TO BE ASSIGNED'].tolist())
            if csv_data:
                g_df = pd.read_csv(StringIO(csv_data))
                g_df.columns = [c.strip().upper() for c in g_df.columns]
                u_lookup = g_df[g_df['TYPE'] == 'USER'].set_index('SEARCH_KEY')['GUID'].to_dict()
                r_lookup = g_df[g_df['TYPE'] == 'ROLE'].set_index('SEARCH_KEY')['GUID'].to_dict()

                # 3. PHASE 3: ASSIGN ROLES
                role_ops = []
                final_summary = []
                for _, row in df.iterrows():
                    u_name, r_name = str(row['USER NAME']), str(row['ROLE TO BE ASSIGNED'])
                    u_guid, r_guid = u_lookup.get(u_name), r_lookup.get(r_name)
                    
                    u_msg = "✅ New" if user_status_map.get(u_name) == "CREATED" else "ℹ️ Existing" if user_status_map.get(u_name) == "EXISTS" else "❌ Error"
                    
                    if u_guid and r_guid:
                        b_id = f"r_{u_name}_{secrets.token_hex(3)}"
                        role_ops.append({
                            "method": "PATCH", "path": f"/Roles/{r_guid}", "bulkId": b_id,
                            "data": {"members": [{"value": u_guid, "operation": "ADD"}]}
                        })
                        final_summary.append({"USER": u_name, "USER_STATUS": u_msg, "ROLE": r_name, "ROLE_STATUS": "⏳ Pending", "BULK_ID": b_id})
                    else:
                        final_summary.append({"USER": u_name, "USER_STATUS": u_msg, "ROLE": r_name, "ROLE_STATUS": "❌ GUID Missing", "BULK_ID": None})

                if role_ops:
                    res_r = execute_scim_bulk(env_url, username, password, role_ops)
                    r_map = {op.get("bulkId"): str(op.get("status", {}).get("code", "")) for op in res_r.json().get("Operations", [])}
                    for item in final_summary:
                        if item["BULK_ID"] in r_map:
                            code = r_map[item["BULK_ID"]]
                            item["ROLE_STATUS"] = "✅ Assigned" if code.startswith("2") else "ℹ️ Already Had Role" if code == "409" else "❌ Failed"

                # Output
                summary_df = pd.DataFrame(final_summary).drop(columns=['BULK_ID'])
                st.subheader("📋 Final Summary")
                st.table(summary_df)

                # Error Log Download
                error_df = summary_df[summary_df.stack().str.contains("❌|Failed").groupby(level=0).any()]
                if not error_df.empty:
                    st.download_button("📥 Download Error Log", error_df.to_csv(index=False), "error_log.csv", "text/csv")
            else:
                st.error("Could not retrieve GUIDs from Oracle report.")

st.markdown("<hr><center>Developed by <b>Raktim Pal</b></center>", unsafe_allow_html=True)
