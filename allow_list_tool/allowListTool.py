import json
import re
import os
import uuid
import tkinter as tk
from urllib.parse import urlparse, parse_qsl, unquote
from tkinter import filedialog, messagebox, ttk

# --- Parsing Functions ---
def parse_log(log_line):
    match = re.search(r'(\{.*?\})', log_line)
    if not match:
        return None
    json_str = match.group(1).strip()
    try:
        log_data = json.loads(json_str)
    except json.JSONDecodeError:
        try:
            fixed_str = json_str.replace("'", '"')
            log_data = json.loads(fixed_str)
        except Exception:
            try:
                fixed_str = re.sub(r'(\{|,)\s*([\w]+)\s*:', r'\1 "\2":', json_str)
                log_data = json.loads(fixed_str)
            except Exception as e:
                print(f"Error parsing log line: {e}\nOriginal string: {json_str}")
                return None

    required_keys = ["url", "processFullPath", "userName", "userGroups"]
    if not all(key in log_data for key in required_keys):
        return None

    # --- New Privilege Creation Logic ---
    decoded_url = unquote(log_data["url"])
    parsed = urlparse(decoded_url)
    base_path = parsed.path
    qp_list = parse_qsl(parsed.query)
    query_parameters = {k: v for k, v in qp_list}
    if qp_list:
        name_suffix = "_".join(v for k, v in qp_list)
        new_name = f"{base_path}_{name_suffix}"
    else:
        new_name = base_path
    new_path = f"{base_path}/{uuid.uuid4()}/{uuid.uuid4()}._ProxyAgentWinVM"

    privilege = {
        "path": new_path,
        "queryParameters": query_parameters,
        "name": new_name
    }
    # --- End of New Privilege Creation Logic ---

    identity_name = f"{os.path.basename(log_data['processFullPath'])}_{log_data['userName']}"
    identity = {
        "name": identity_name,
        "userName": log_data["userName"],
        "groupName": log_data["userGroups"],
        "processName": os.path.basename(log_data["processFullPath"]),
        "exePath": log_data["processFullPath"]
    }
    return privilege, identity

def generate_allow_list(log_lines):
    privileges_set = {}
    identities_set = {}
    for line in log_lines:
        result = parse_log(line)
        if result:
            privilege, identity = result
            privileges_set[privilege["name"]] = privilege
            identities_set[identity["name"]] = identity
    return list(privileges_set.values()), list(identities_set.values())

# --- GUI Application ---
class AllowListApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Allow List Generator")
        self.master.geometry("1100x650")
        self.master.configure(bg="#f0f8ff")

        # Data storage
        self.log_lines = None
        self.privileges = []
        self.identities = []
        self.roles = {}            # {role_name: [privilege names]}
        self.role_assignments = [] # list of {"role": role_name, "identities": [identity names]}
        self.allow_list = {}

        # Left panel with navigation buttons (numbered)
        self.left_frame = tk.Frame(master, bg="#e6f2ff", padx=10, pady=10)
        self.left_frame.grid(row=0, column=0, sticky="ns")

        # Make all buttons the same width (e.g., 30)
        btn_width = 30
        btn_readme = tk.Button(self.left_frame, text="ReadMe", width=btn_width, command=self.show_readme, bg="#99ccff")
        btn_upload = tk.Button(self.left_frame, text="Step 1: Upload Logs", width=btn_width, command=self.upload_logs, bg="#99ccff")
        btn_parsed = tk.Button(self.left_frame, text="Step 2: Parsed Data", width=btn_width, command=lambda: self.show_frame(self.frame_parsed), bg="#99ccff")
        btn_edit = tk.Button(self.left_frame, text="Step 3: Edit Parsed Data", width=btn_width, command=lambda: self.show_frame(self.frame_edit), bg="#99ccff")
        btn_create_role = tk.Button(self.left_frame, text="Step 4: Create Role", width=btn_width, command=lambda: self.show_frame(self.frame_create_role), bg="#99ccff")
        btn_create_assignment = tk.Button(self.left_frame, text="Step 5: Create Role Assignment", width=btn_width, command=lambda: self.show_frame(self.frame_create_assignment), bg="#99ccff")
        btn_allow_list = tk.Button(self.left_frame, text="Step 6: Allow List", width=btn_width, command=self.view_allow_list, bg="#99ccff")
        btn_download = tk.Button(self.left_frame, text="Step 7: Download Allow List", width=btn_width, command=self.download_allow_list, bg="#99ccff")

        btn_readme.pack(pady=5)
        btn_upload.pack(pady=5)
        btn_parsed.pack(pady=5)
        btn_edit.pack(pady=5)
        btn_create_role.pack(pady=5)
        btn_create_assignment.pack(pady=5)
        btn_allow_list.pack(pady=5)
        btn_download.pack(pady=5)

        # Right panel with container for frames
        self.right_frame = tk.Frame(master, bg="#ffffff", padx=10, pady=10)
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        master.grid_columnconfigure(1, weight=1)
        master.grid_rowconfigure(0, weight=1)

        # Create frames for each view (stacked in the same cell)
        self.frame_readme = tk.Frame(self.right_frame, bg="#f0f8ff")
        self.frame_parsed = tk.Frame(self.right_frame, bg="#fffacd")
        self.frame_edit = tk.Frame(self.right_frame, bg="#fffacd")
        self.frame_create_role = tk.Frame(self.right_frame, bg="#e6f2ff")
        self.frame_create_assignment = tk.Frame(self.right_frame, bg="#e0ffe0")  # Changed to green
        self.frame_allow_list = tk.Frame(self.right_frame, bg="#e6e6fa")

        for frame in (
            self.frame_readme,
            self.frame_parsed,
            self.frame_edit,
            self.frame_create_role,
            self.frame_create_assignment,
            self.frame_allow_list
        ):
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)

        # --- Frame: ReadMe ---
        # Instead of two labels, we use one Text widget that fills the frame.
        # Create the Text widget with no extra padding
        self.txt_readme = tk.Text(self.frame_readme, wrap="word", bg="#f0f8ff", bd=0, highlightthickness=0)
        self.txt_readme.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.frame_readme.grid_rowconfigure(0, weight=1)
        self.frame_readme.grid_columnconfigure(0, weight=1)

        # Configure tags: header in Arial 12 Bold, body in Consolas 10
        self.txt_readme.tag_configure("header", font=("Arial", 12, "bold"))
        self.txt_readme.tag_configure("body", font=("Consolas", 10))

        # Insert header text with the header tag
        self.txt_readme.insert(tk.END, "How to Use Tool\n\n", "header")

        # Insert the rest of the instructions with the body tag
        body_text = (
            "Use guest agent generic logs kusto query to get log_connection_summary\n"
            "or upload ProxyAgentConnection.log. Refer to aka.ms/msp-publicpreview for an example kusto query.\n\n"
            "To use the tool, start at Step 1 and upload the log connection summary by either running the kusto "
            "query example from the public docs or\n"
            "directly uploading the log file named ProxyAgentConnection.log from inside the VM.\n"
        )
        self.txt_readme.insert(tk.END, body_text, "body")
        self.txt_readme.config(state=tk.DISABLED)

        # --- Frame: Parsed Data (read-only) ---
        lbl_parsed = tk.Label(self.frame_parsed, text="Parsed Data", bg="#fffacd", font=("Arial", 12, "bold"))
        lbl_parsed.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.txt_parsed = tk.Text(self.frame_parsed, wrap="none", bg="#fffacd", font=("Consolas", 10))
        self.txt_parsed.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # --- Frame: Edit Parsed Data (editable) ---
        lbl_edit = tk.Label(self.frame_edit, text="Edit Parsed Privileges and Identities", bg="#fffacd", font=("Arial", 12, "bold"))
        lbl_edit.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.txt_edit = tk.Text(self.frame_edit, wrap="none", bg="#fffacd", font=("Consolas", 10))
        self.txt_edit.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        btn_save = tk.Button(self.frame_edit, text="Save Edits", command=self.save_edits, bg="#99ccff", font=("Arial", 12))
        btn_save.grid(row=2, column=0, sticky="e", padx=5, pady=5)

        # --- Frame: Create Role ---
        lbl_role_title = tk.Label(self.frame_create_role, text="Create Role", bg="#e6f2ff", font=("Arial", 12, "bold"))
        lbl_role_title.grid(row=0, column=0, sticky="nw", padx=5, pady=(0, 0))
        lbl_role_desc = tk.Label(self.frame_create_role, text="Roles are a grouping of privileges", bg="#e6f2ff", font=("Arial", 10))
        lbl_role_desc.grid(row=1, column=0, sticky="nw", padx=5, pady=(0, 0))
        lbl_role_name = tk.Label(self.frame_create_role, text="Role Name:", bg="#e6f2ff", font=("Arial", 12))
        lbl_role_name.grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        self.entry_role_name = tk.Entry(self.frame_create_role, width=40, font=("Arial", 12))
        self.entry_role_name.grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        lbl_select_priv = tk.Label(self.frame_create_role, text="Select Privileges (Ctrl+Click):", bg="#e6f2ff", font=("Arial", 12))
        lbl_select_priv.grid(row=4, column=0, sticky="nw", padx=5, pady=5)
        self.lb_privileges = tk.Listbox(self.frame_create_role, selectmode=tk.MULTIPLE, width=50, font=("Consolas", 10))
        self.lb_privileges.grid(row=5, column=0, sticky="nsew", padx=5, pady=5)
        btn_add_role = tk.Button(self.frame_create_role, text="Add Role", command=self.add_role, bg="#99ccff", font=("Arial", 12))
        btn_add_role.grid(row=6, column=0, sticky="e", padx=5, pady=5)
        self.frame_create_role.grid_rowconfigure(5, weight=1)

        # --- Frame: Create Role Assignment (Green background) ---
        lbl_assign_title = tk.Label(self.frame_create_assignment, text="Create Role Assignment", bg="#e0ffe0", font=("Arial", 12, "bold"))
        lbl_assign_title.grid(row=0, column=0, sticky="nw", padx=5, pady=(0, 0))
        lbl_assign_desc = tk.Label(self.frame_create_assignment, text="Role Assignments consists of a role and the list of identities granted access for that role", bg="#e0ffe0", font=("Arial", 10))
        lbl_assign_desc.grid(row=1, column=0, sticky="nw", padx=5, pady=(0, 0))
        lbl_role_select = tk.Label(self.frame_create_assignment, text="Select Role:", bg="#e0ffe0", font=("Arial", 12))
        lbl_role_select.grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        self.combo_role = ttk.Combobox(self.frame_create_assignment, state="readonly", width=40, font=("Arial", 12))
        self.combo_role.grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        lbl_select_ident = tk.Label(self.frame_create_assignment, text="Select Identities (Ctrl+Click):", bg="#e0ffe0", font=("Arial", 12))
        lbl_select_ident.grid(row=4, column=0, sticky="nw", padx=5, pady=5)
        self.lb_identities = tk.Listbox(self.frame_create_assignment, selectmode=tk.MULTIPLE, width=50, font=("Consolas", 10))
        self.lb_identities.grid(row=5, column=0, sticky="nsew", padx=5, pady=5)
        btn_add_assign = tk.Button(self.frame_create_assignment, text="Add Assignment", command=self.add_assignment, bg="#99cc99", font=("Arial", 12))
        btn_add_assign.grid(row=6, column=0, sticky="e", padx=5, pady=5)
        self.frame_create_assignment.grid_rowconfigure(5, weight=1)

        # --- Frame: Allow List ---
        lbl_allow_title = tk.Label(self.frame_allow_list, text="Final Allow List", bg="#e6e6fa", font=("Arial", 12, "bold"))
        lbl_allow_title.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.txt_allowlist = tk.Text(self.frame_allow_list, wrap="none", bg="#e6e6fa", font=("Consolas", 10))
        self.txt_allowlist.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.frame_allow_list.grid_rowconfigure(1, weight=1)

        # Show the Parsed Data frame first
        self.show_frame(self.frame_parsed)

    def show_frame(self, frame):
        frame.tkraise()

    def show_readme(self):
        self.show_frame(self.frame_readme)

    def update_parsed_display(self):
        self.txt_parsed.delete("1.0", tk.END)
        text = "Privileges:\n"
        for priv in self.privileges:
            text += f"  {priv['name']}\n"
        text += "\nIdentities:\n"
        for ident in self.identities:
            text += f"  {ident['name']}\n"
        self.txt_parsed.insert(tk.END, text)
        # Also update the editable text area in the Edit Parsed Data view
        parsed_data = {"privileges": self.privileges, "identities": self.identities}
        self.txt_edit.delete("1.0", tk.END)
        self.txt_edit.insert(tk.END, json.dumps(parsed_data, indent=4))

    def save_edits(self):
        try:
            edited = json.loads(self.txt_edit.get("1.0", tk.END))
            self.privileges = edited.get("privileges", [])
            self.identities = edited.get("identities", [])
            messagebox.showinfo("Saved", "Parsed data updated successfully.")
            self.update_parsed_display()
            # Refresh listboxes for role creation
            self.lb_privileges.delete(0, tk.END)
            for priv in self.privileges:
                self.lb_privileges.insert(tk.END, priv["name"])
            self.lb_identities.delete(0, tk.END)
            for ident in self.identities:
                self.lb_identities.insert(tk.END, ident["name"])
        except Exception as e:
            messagebox.showerror("Error", f"Error parsing JSON: {e}")

    def build_allow_list(self):
        used_privilege_names = set()
        for role, privs in self.roles.items():
            used_privilege_names.update(privs)
        filtered_privileges = [p for p in self.privileges if p["name"] in used_privilege_names]

        used_identity_names = set()
        for assignment in self.role_assignments:
            used_identity_names.update(assignment["identities"])
        filtered_identities = [i for i in self.identities if i["name"] in used_identity_names]

        self.allow_list = {
            "privileges": filtered_privileges,
            "identities": filtered_identities,
            "roles": [{"name": role, "privileges": self.roles[role]} for role in self.roles],
            "roleAssignments": self.role_assignments
        }
        return json.dumps(self.allow_list, indent=4)

    def update_allow_list_display(self):
        self.txt_allowlist.delete("1.0", tk.END)
        self.txt_allowlist.insert(tk.END, self.build_allow_list())

    def upload_logs(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        try:
            with open(file_path, "r") as f:
                self.log_lines = f.readlines()
            self.privileges, self.identities = generate_allow_list(self.log_lines)
            messagebox.showinfo(
                "Upload Complete",
                f"Found {len(self.privileges)} privileges and {len(self.identities)} identities."
            )
            self.update_parsed_display()
            self.lb_privileges.delete(0, tk.END)
            for priv in self.privileges:
                self.lb_privileges.insert(tk.END, priv["name"])
            self.lb_identities.delete(0, tk.END)
            for ident in self.identities:
                self.lb_identities.insert(tk.END, ident["name"])
        except Exception as e:
            messagebox.showerror("Error", f"Error opening log file: {e}")

    def add_role(self):
        role_name = self.entry_role_name.get().strip()
        if not role_name:
            messagebox.showwarning("Input Error", "Role name cannot be empty.")
            return
        selected_indices = self.lb_privileges.curselection()
        if not selected_indices:
            messagebox.showwarning("Input Error", "Please select at least one privilege.")
            return
        selected_privileges = [self.lb_privileges.get(i) for i in selected_indices]
        self.roles[role_name] = selected_privileges
        messagebox.showinfo("Role Created",
                            f"Role '{role_name}' created with privileges:\n{selected_privileges}")
        self.entry_role_name.delete(0, tk.END)
        self.lb_privileges.selection_clear(0, tk.END)
        self.combo_role['values'] = list(self.roles.keys())

    def add_assignment(self):
        role_selected = self.combo_role.get()
        if not role_selected:
            messagebox.showwarning("Input Error", "Please select a role.")
            return
        selected_indices = self.lb_identities.curselection()
        selected_identities = [self.lb_identities.get(i) for i in selected_indices]
        assignment = {"role": role_selected, "identities": selected_identities}
        self.role_assignments.append(assignment)
        messagebox.showinfo("Assignment Created",
                            f"Assignment for role '{role_selected}' created:\n{assignment}")
        self.lb_identities.selection_clear(0, tk.END)

    def view_allow_list(self):
        self.update_allow_list_display()
        self.show_frame(self.frame_allow_list)

    def download_allow_list(self):
        self.update_allow_list_display()
        outfile = filedialog.asksaveasfilename(
            title="Save Allow List As",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if outfile:
            try:
                with open(outfile, "w") as f:
                    json.dump(self.allow_list, f, indent=4)
                messagebox.showinfo("Success", f"Allow list saved to {outfile}")
            except Exception as e:
                messagebox.showerror("Error", f"Error writing to file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AllowListApp(root)
    root.mainloop()