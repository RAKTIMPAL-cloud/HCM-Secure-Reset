import streamlit as st
import requests
import pandas as pd
import base64
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
import string
import secrets

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM: User & Multi-Role Creator", layout="wide")
st.title("👤 Oracle HCM: Bulk User & Multi-Role Management")

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
    
    user_str = ",".join(filter(None, set(usernames))) # Unique usernames
    role_str = ",".join(filter(None, set(roles)))     # Unique roles

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
        res = requests.post(full_url, data=soap_request, headers=headers)
        root = ET.fromstring(res.content)
        ns = {'ns': 'http://xmlns.oracle.com/oxp/service/PublicReportService'}
        report_bytes = root.find('.//ns:reportBytes', ns)
        if report_bytes is not None and report_bytes.text:
            return base64.b64decode(report_bytes.text).decode("utf-8")
        return None
    except Exception as e:
        st.error(f"SOAP Error: {e}")
        return None

def execute_scim_bulk(env_url, admin_user, admin_pwd, operations):
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    payload = {
        "schemas": ["urn:scim:schemas:core:2.0:BulkRequest"],
        "failOnErrors": 1,
        "Operations": operations
    }
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
    # Matching your provided Excel structure
    template_df = pd.DataFrame(columns=['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL', 'ROLE TO BE ASSIGNED'])
    tmp_buff = BytesIO()
    with pd.ExcelWriter(tmp_buff, engine='xlsxwriter') as writer:
        template_df.to_excel(writer, index=False)
    st.download_button("📥 Download Template", tmp_buff.getvalue(), "Oracle_User_Role_Template.xlsx")
    uploaded_file = st.file_uploader("Upload Excel", type=["xlsx"])

# --- Execution ---
if st.button("🚀 Process Bulk Creation & Assignments"):
    if not (username and password and uploaded_file):
        st.warning("Please fill all details and upload the Excel.")
    else:
        try:
            df = pd.read_excel(uploaded_file)
            df.columns = [c.strip().upper() for c in df.columns]
            common_pwd = generate_secure_password()
            
            # Identify unique users for Phase 1
            unique_users_df = df.drop_duplicates(subset=['USER NAME'])
            
            # --- PHASE 1: CREATE USERS ---
            user_ops = []
            for _, row in unique_users_df.iterrows():
                user_ops.append({
                    "method": "POST", "path": "/Users", "bulkId": str(row['USER NAME']),
                    "data": {
                        "schemas": ["urn:scim:schemas:core:2.0:User"],
                        "userName": str(row['USER NAME']).strip(),
                        "name": {"familyName": str(row['LAST NAME']).strip(), "givenName": str(row['FIRST NAME']).strip()},
                        "emails": [{"primary": True, "value": str(row['WORK EMAIL']).strip(), "type": "W"}],
                        "active": True, "password": common_pwd
                    }
                })
            
            with st.spinner(f"⏳ Phase 1: Creating {len(user_ops)} Unique Users..."):
                res_users = execute_scim_bulk(env_url, username, password, user_ops)
            
            if res_users.status_code in [200, 201]:
                st.success(f"✅ Users processed. Temporary Password: `{common_pwd}`")
                
                # --- PHASE 2: FETCH GUIDs ---
                with st.spinner("⏳ Phase 2: Resolving GUIDs for Users and Roles..."):
                    all_usernames = df['USER NAME'].astype(str).tolist()
                    all_roles = df['ROLE TO BE ASSIGNED'].astype(str).tolist()
                    csv_data = fetch_guids_via_soap(env_url, username, password, all_usernames, all_roles)
                    
                if csv_data:
                    guid_map_df = pd.read_csv(StringIO(csv_data))
                    guid_map_df.columns = [c.strip().upper() for c in guid_map_df.columns]
                    
                    user_guid_lookup = guid_map_df[guid_map_df['TYPE'] == 'USER'].set_index('SEARCH_KEY')['GUID'].to_dict()
                    role_guid_lookup = guid_map_df[guid_map_df['TYPE'] == 'ROLE'].set_index('SEARCH_KEY')['GUID'].to_dict()

                    # --- PHASE 3: ASSIGN ROLES ---
                    role_ops = []
                    summary_results = []
                    
                    for _, row in df.iterrows():
                        u_name = str(row['USER NAME']).strip()
                        r_name = str(row['ROLE TO BE ASSIGNED']).strip()
                        u_guid = user_guid_lookup.get(u_name)
                        r_guid = role_guid_lookup.get(r_name)
                        
                        if u_guid and r_guid:
                            role_ops.append({
                                "method": "PATCH",
                                "path": f"/Roles/{r_guid}",
                                "bulkId": f"assign_{u_name}_{secrets.token_hex(4)}",
                                "data": {"members": [{"value": u_guid, "operation": "ADD"}]}
                            })
                            summary_results.append({"USER NAME": u_name, "ROLE": r_name, "OUTCOME": "✅ Assignment Sent"})
                        else:
                            fail_reason = "User GUID Missing" if not u_guid else "Role GUID Missing"
                            summary_results.append({"USER NAME": u_name, "ROLE": r_name, "OUTCOME": f"❌ Failed ({fail_reason})"})
                    
                    if role_ops:
                        with st.spinner(f"⏳ Phase 3: Sending {len(role_ops)} Role Assignments..."):
                            res_roles = execute_scim_bulk(env_url, username, password, role_ops)
                            if res_roles.status_code in [200, 201]:
                                st.success("✅ Bulk Role assignments completed!")
                    
                    st.divider()
                    st.subheader("📋 Final Summary")
                    st.table(pd.DataFrame(summary_results))
                else:
                    st.error("BIP Report returned no data. Ensure report path and SQL are correct.")
            else:
                st.error(f"Phase 1 failed: {res_users.text}")
        except Exception as e:
            st.error(f"System Error: {e}")

st.markdown("<hr><div style='text-align: center; color: yellow;'>Developed by <b>Raktim Pal</b></div>", unsafe_allow_html=True)
