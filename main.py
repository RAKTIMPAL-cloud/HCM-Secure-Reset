import streamlit as st
import requests
import pandas as pd
import base64
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
import string
import secrets

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM Smart Creator", layout="wide")
# --- Logo Header Section ---
log_col1, log_col2, log_col3 = st.columns([1, 4, 1])
with log_col1:
    st.image("https://upload.wikimedia.org/wikipedia/commons/5/50/Oracle_logo.svg", width=150)
with log_col3:
    st.image("https://www.ibm.com/brand/experience-guides/developer/8f4e3cc2b5d52354a6d43c8edba1e3c9/02_8-bar-reverse.svg", width=120)

st.title("👤 Oracle HCM: Bulk User & Role Management")

# --- Functions ---

def generate_secure_password(length=12):
    """Generates a random secure password meeting Oracle complexity requirements."""
    alphabet = string.ascii_letters + string.digits + "!#$%"
    # FIX: Removed the extra 'string.choice' call that caused the AttributeError
    pwd = [
        secrets.choice(string.ascii_uppercase), 
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits), 
        secrets.choice("!#$%")
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def fetch_guids_via_soap(env_url, admin_user, admin_pwd, usernames, roles):
    full_url = env_url.rstrip("/") + "/xmlpserver/services/ExternalReportWSSService"
    report_path = "/Custom/Human Capital Management/PASSWORD/User_Role_GUID_Report.xdo"
    
    user_str = ",".join(filter(None, set([str(u).strip() for u in usernames])))
    role_str = ",".join(filter(None, set([str(r).strip() for r in roles])))

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
                <pub:sizeOfDataChunkDownload>-1</pub:sizeOfDataChunkDownload>
             </pub:reportRequest>
          </pub:runReport>
       </soap:Body>
    </soap:Envelope>"""
    
    auth = base64.b64encode(f"{admin_user}:{admin_pwd}".encode()).decode()
    headers = {"Content-Type": "application/soap+xml; charset=utf-8", "Authorization": f"Basic {auth}"}

    try:
        res = requests.post(full_url, data=soap_request, headers=headers, timeout=45)
        if res.status_code != 200: return None
        root = ET.fromstring(res.content)
        ns = {'ns': 'http://xmlns.oracle.com/oxp/service/PublicReportService'}
        report_bytes = root.find('.//ns:reportBytes', ns)
        if report_bytes is not None and report_bytes.text:
            return base64.b64decode(report_bytes.text).decode("utf-8")
        return None
    except:
        return None

def execute_scim_bulk(env_url, admin_user, admin_pwd, operations):
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    payload = {
        "schemas": ["urn:scim:schemas:core:2.0:BulkRequest"],
        "failOnErrors": 1,
        "Operations": operations
    }
    try:
        response = requests.post(scim_url, json=payload, auth=(admin_user, admin_pwd), timeout=60)
        return response
    except Exception as e:
        return str(e)

# --- UI Layout ---
col1, col2 = st.columns(2)
with col1:
    st.subheader("🌐 Connection")
    env_url = st.text_input("URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data")
    
    # Template Generation
    template_df = pd.DataFrame(columns=['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL', 'ROLE TO BE ASSIGNED'])
    tmp_buff = BytesIO()
    with pd.ExcelWriter(tmp_buff, engine='xlsxwriter') as writer:
        template_df.to_excel(writer, index=False)
    
    st.download_button(
        label="📥 Download Template",
        data=tmp_buff.getvalue(),
        file_name="User_Role_Template.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    uploaded_file = st.file_uploader("Upload Completed Excel", type=["xlsx"])

# --- Processing ---
if st.button("🚀 Process Bulk Operations"):
    if not (username and password and uploaded_file):
        st.warning("Please fill all details.")
    else:
        df = pd.read_excel(uploaded_file)
        df.columns = [c.strip().upper() for c in df.columns]
        common_pwd = generate_secure_password()
        
        # 1. PHASE 1: CREATE USERS
        unique_users_df = df.drop_duplicates(subset=['USER NAME'])
        user_ops = []
        for _, row in unique_users_df.iterrows():
            user_ops.append({
                "method": "POST", "path": "/Users", "bulkId": str(row['USER NAME']).strip(),
                "data": {
                    "schemas": ["urn:scim:schemas:core:2.0:User"],
                    "userName": str(row['USER NAME']).strip(),
                    "name": {"familyName": str(row['LAST NAME']).strip(), "givenName": str(row['FIRST NAME']).strip()},
                    "emails": [{"primary": True, "value": str(row['WORK EMAIL']).strip(), "type": "W"}],
                    "active": True, "password": common_pwd
                }
            })

        user_status_map = {}
        with st.spinner("⏳ Step 1: Processing User Creation..."):
            u_res = execute_scim_bulk(env_url, username, password, user_ops)
            
            if isinstance(u_res, str):
                st.error(f"Connection Failed: {u_res}")
            elif u_res.status_code == 401: st.error("❌ 401 Unauthorized: Invalid Credentials")
            elif u_res.status_code == 403: st.error("❌ 403 Forbidden: Check URL or Permissions")
            elif u_res.status_code == 400: st.error("❌ 400 Bad Request: Payload Error")
            elif u_res.status_code in [200, 201]:
                for op in u_res.json().get("Operations", []):
                    code = str(op.get("status", {}).get("code", ""))
                    u_id = op.get("bulkId")
                    if code == "201": user_status_map[u_id] = "✅ Created Successfully"
                    elif code == "409": user_status_map[u_id] = "ℹ️ Already Exists"
                    else: user_status_map[u_id] = f"❌ Error {code}"

        # 2. PHASE 2: RESOLVE GUIDs
        with st.spinner("⏳ Step 2: Fetching GUIDs..."):
            csv_data = fetch_guids_via_soap(env_url, username, password, df['USER NAME'].tolist(), df['ROLE TO BE ASSIGNED'].tolist())
            
        if csv_data:
            g_df = pd.read_csv(StringIO(csv_data))
            g_df.columns = [c.strip().upper() for c in g_df.columns]
            u_map = g_df[g_df['TYPE'] == 'USER'].set_index('SEARCH_KEY')['GUID'].to_dict()
            r_map = g_df[g_df['TYPE'] == 'ROLE'].set_index('SEARCH_KEY')['GUID'].to_dict()

            # 3. PHASE 3: ASSIGN ROLES
            role_ops = []
            tracking_list = []
            for _, row in df.iterrows():
                u_name, r_name = str(row['USER NAME']).strip(), str(row['ROLE TO BE ASSIGNED']).strip()
                u_guid, r_guid = u_map.get(u_name), r_map.get(r_name)
                b_id = f"r_{u_name}_{secrets.token_hex(2)}"
                
                if u_guid and r_guid:
                    role_ops.append({
                        "method": "PATCH", "path": f"/Roles/{r_guid}", "bulkId": b_id,
                        "data": {"members": [{"value": u_guid, "operation": "ADD"}]}
                    })
                    tracking_list.append({"USER": u_name, "ROLE": r_name, "USER_STATUS": user_status_map.get(u_name, "N/A"), "B_ID": b_id})
                else:
                    tracking_list.append({"USER": u_name, "ROLE": r_name, "USER_STATUS": user_status_map.get(u_name, "N/A"), "ROLE_STATUS": "❌ GUID Missing", "B_ID": None})

            if role_ops:
                with st.spinner("⏳ Step 3: Assigning Roles..."):
                    r_res = execute_scim_bulk(env_url, username, password, role_ops)
                    if r_res.status_code in [200, 201]:
                        r_results = {op.get("bulkId"): str(op.get("status", {}).get("code", "")) for op in r_res.json().get("Operations", [])}
                        for item in tracking_list:
                            if item["B_ID"] in r_results:
                                code = r_results[item["B_ID"]]
                                item["ROLE_STATUS"] = "✅ Processed" if code == "204" else f"❌ Error {code}"

            # --- DISPLAY RESULTS ---
            st.divider()
            st.subheader("📋 Final Execution Summary")
            
            # HIGHLIGHTED PASSWORD BLOCK
            st.markdown(
                f"""
                <div style="background-color:#FFF3CD; padding:15px; border-radius:10px; border: 2px solid #FFEEBA; margin-bottom:20px;">
                    <h4 style="color:#856404; margin:0; font-family:sans-serif;">🔑 Temporary Password: 
                        <span style="background-color:#FFFF00; color:black; padding:4px 8px; border-radius:4px; font-weight:bold; border:1px solid #d4d400;">{common_pwd}</span>
                    </h4>
                    <p style="color:#856404; margin-top:5px; font-size:0.9rem;">Copy this password for all newly created users. Don't use this password for "Already Exists" users</p>
                </div>
                """, 
                unsafe_allow_html=True
            )

            final_df = pd.DataFrame(tracking_list).drop(columns=['B_ID'])
            st.table(final_df)
            
            with st.expander("🛠️ View Raw API Response (Debug)"):
                if 'r_res' in locals() and hasattr(r_res, 'json'):
                    st.json(r_res.json())
                else:
                    st.write("No API response data available.")
        else:
            st.error("🚨 Error: Could not retrieve GUIDs from Oracle. Please verify the BIP report path and your permissions.")

# Footer
st.markdown("""
<hr style="margin-top: 50px;">
<div style='text-align: center; color: yellow; font-size: 0.85em;'>
    <p>App has been developed by <strong>Raktim Pal</strong></p>
    <p>© 2026 Raktim Pal. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
