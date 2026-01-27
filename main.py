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

# --- Logic Functions ---

def generate_secure_password(length=12):
    """Generates a single secure password for the entire batch."""
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!#$%"
    all_chars = upper + lower + digits + special
    
    pwd = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    pwd += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def create_bulk_users(env_url, admin_user, admin_pwd, df, common_pwd):
    """Executes Bulk POST via SCIM REST API using a common password."""
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    
    operations = []

    for index, row in df.iterrows():
        u_name = str(row['USER NAME']).strip()
        f_name = str(row['FIRST NAME']).strip()
        l_name = str(row['LAST NAME']).strip()
        email = str(row['WORK EMAIL']).strip()
        
        user_op = {
            "method": "POST",
            "path": "/Users",
            "bulkId": u_name,
            "data": {
                "schemas": ["urn:scim:schemas:core:2.0:User"],
                "userName": u_name,
                "name": {
                    "familyName": l_name,
                    "givenName": f_name
                },
                "emails": [{
                    "primary": True,
                    "value": email,
                    "type": "W"
                }],
                "active": True,
                "password": common_pwd  # Using the common batch password
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

# --- UI Layout ---
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🌐 Connection Details")
    env_url = st.text_input("Environment URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data Upload")
    
    # Template Generation
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

# --- Execution ---

if st.button("🚀 Create Bulk Users"):
    if not (username and password and uploaded_file):
        st.warning("⚠️ Please provide credentials and upload an Excel file.")
    else:
        try:
            df = pd.read_excel(uploaded_file)
            df.columns = [c.strip().upper() for c in df.columns]
            
            required_cols = ['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL']
            
            if all(col in df.columns for col in required_cols):
                # Generate the one-time common password for this session
                batch_password = generate_secure_password()
                
                with st.spinner("📡 Processing Bulk User Creation..."):
                    res = create_bulk_users(env_url, username, password, df, batch_password)
                    
                    if res.status_code in [200, 201]:
                        st.success("🎊 Process Complete!")
                        st.info(f"🔑 **Common Password Set for All Users:** `{batch_password}`")
                        
                        results = res.json().get("Operations", [])
                        display_data = []
                        
                        for op in results:
                            u_id = op.get("bulkId")
                            status_code = str(op.get("status", {}).get("code", ""))
                            
                            if status_code.startswith("2"):
                                outcome = "✅ User Created Successfully"
                            elif status_code == "409":
                                outcome = "❌ Failed: User already exists"
                            else:
                                detail = op.get("response", {}).get("detail", "Unknown Error")
                                outcome = f"❌ Failed: {detail}"
                            
                            display_data.append({
                                "USER NAME": u_id,
                                "OUTCOME": outcome
                            })
                        
                        st.table(pd.DataFrame(display_data))
                    else:
                        st.error(f"❌ Connection Failed: {res.status_code}")
            else:
                st.error(f"❌ Missing columns: {required_cols}")
        
        except Exception as e:
            st.error(f"🔥 Error: {e}")

# Footer
st.markdown("""
<hr style="margin-top: 50px;">
<div style='text-align: center; color: yellow; font-size: 0.85em;'>
    <p>App has been developed by <strong>Raktim Pal</strong></p>
    <p>© 2026 Raktim Pal. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
