import streamlit as st
import requests
import pandas as pd
import json
import string
import secrets
from io import BytesIO

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM Bulk User Creator", layout="wide")
st.title("👤 Oracle HCM Bulk User Creator")

# --- UI Layout ---
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🌐 Connection Details")
    env_url = st.text_input("Environment URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data Upload")
    
    # Template Download Logic
    template_df = pd.DataFrame(columns=['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL'])
    template_buffer = BytesIO()
    with pd.ExcelWriter(template_buffer, engine='xlsxwriter') as writer:
        template_df.to_excel(writer, index=False)
    
    st.download_button(
        label="📥 Download Excel Template",
        data=template_buffer.getvalue(),
        file_name="Oracle_User_Template.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    
    uploaded_file = st.file_uploader("Upload Completed Excel", type=["xlsx"])

# --- Logic Functions ---

def create_bulk_users(env_url, admin_user, admin_pwd, df):
    """Executes Bulk POST via SCIM REST API to create users."""
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    
    operations = []
    
    for index, row in df.iterrows():
        # Mapping Excel columns to SCIM JSON Structure
        # We use .get() to avoid KeyErrors and strip() to clean data
        u_name = str(row['USER NAME']).strip()
        f_name = str(row['FIRST NAME']).strip()
        l_name = str(row['LAST NAME']).strip()
        email = str(row['WORK EMAIL']).strip()

        user_op = {
            "method": "POST",
            "path": "/Users",
            "bulkId": f"user_{index}",
            "data": {
                "schemas": ["urn:scim:schemas:core:2.0:User"],
                "userName": u_name,
                "name": {
                    "familyName": l_name,
                    "givenName": f_name # You can concatenate Middle Name here if added to Excel
                },
                "emails": [{
                    "primary": True,
                    "value": email,
                    "type": "W"
                }],
                "active": True,
                "password": "Welcome1"
            }
        }
        operations.append(user_op)

    payload = {
        "schemas": ["urn:scim:schemas:core:2.0:BulkRequest"],
        "failOnErrors": 1,
        "Operations": operations
    }

    response = requests.post(
        scim_url,
        json=payload,
        auth=(admin_user, admin_pwd),
        headers={"Content-Type": "application/json"}
    )
    return response

# --- Main Logic ---

if st.button("🚀 Create Bulk Users"):
    if not (username and password and uploaded_file):
        st.warning("⚠️ Please provide credentials and upload an Excel file.")
    else:
        try:
            df = pd.read_excel(uploaded_file)
            # Standardize columns to Upper Case
            df.columns = [c.strip().upper() for c in df.columns]
            
            required_cols = ['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL']
            
            if all(col in df.columns for col in required_cols):
                with st.spinner("📡 Sending Bulk Request to Oracle HCM..."):
                    res = create_bulk_users(env_url, username, password, df)
                    
                    if res.status_code in [200, 201]:
                        st.success("🎊 Bulk Creation Processed!")
                        
                        results = res.json().get("Operations", [])
                        status_rows = []
                        for i, op in enumerate(results):
                            status_code = str(op.get("status", {}).get("code", "N/A"))
                            # Extract error message if it failed
                            error_msg = op.get("response", {}).get("detail", "") if not status_code.startswith("2") else ""
                            
                            status_rows.append({
                                "User Name": df.iloc[i]['USER NAME'],
                                "Status": status_code,
                                "Outcome": "✅ Created" if status_code.startswith("2") else f"❌ Failed: {error_msg}"
                            })
                        st.table(pd.DataFrame(status_rows))
                    else:
                        st.error(f"❌ API Connection Error: {res.status_code}")
                        st.json(res.json()) # Show full error for debugging
            else:
                st.error(f"❌ Missing columns. Required: {required_cols}")
        
        except Exception as e:
            st.error(f"🔥 An error occurred: {e}")

# Footer
st.markdown("""
<hr style="margin-top: 50px;">
<div style='text-align: center; color: yellow; font-size: 0.85em;'>
    <p>App has been developed by <strong>Raktim Pal</strong></p>
    <p>© 2026 Raktim Pal. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
