
import os
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_db_connection


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-key-change-this"
)


# ==========================================
# LOGIN PROTECTION
# ==========================================

def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    return wrapper


def admin_required(route_function):
    @wraps(route_function)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get("account_role") != "admin":
            return "You do not have permission to access this page.", 403
        return route_function(*args, **kwargs)
    return wrapper


# ==========================================
# PROJECT MEMBERSHIP
# ==========================================

def get_project_role(cursor, user_id, project_id):
    cursor.execute("""
        SELECT role
        FROM project_members
        WHERE user_id = %s AND project_id = %s
    """, (user_id, int(project_id)))

    result = cursor.fetchone()
    return result[0] if result else None


# ==========================================
# BUG PERMISSIONS
# ==========================================

def can_manage_bug(cursor, user_id, bug_id):

    # Admin can manage every bug.
    if session.get("account_role") == "admin":
        cursor.execute(
            "SELECT 1 FROM bug WHERE bug_id = %s",
            (bug_id,)
        )
        return cursor.fetchone() is not None

    cursor.execute("""
        SELECT created_by, visibility, project_id
        FROM bug
        WHERE bug_id = %s
    """, (bug_id,))

    bug = cursor.fetchone()

    if not bug:
        return False

    created_by, visibility, project_id = bug

    if visibility == "private":
        return created_by == user_id

    if visibility == "shared":
        return get_project_role(cursor, user_id, project_id) == "owner"

    return False


# ==========================================
# 1. LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        if session.get("account_role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()

        if connection is None:
            return "Database connection failed."

        try:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT user_id, username, password_hash,
                       account_role, is_active
                FROM users
                WHERE username = %s
            """, (username,))

            user = cursor.fetchone()
            cursor.close()

            if user and user[4] and check_password_hash(user[2], password):

                session.clear()

                session["user_id"] = user[0]
                session["username"] = user[1]
                session["account_role"] = user[3]

                if user[3] == "admin":
                    return redirect(url_for("admin_dashboard"))

                return redirect(url_for("home"))

            return render_template(
                "login.html",
                error="Invalid username/password or account is inactive."
            )

        except Exception as e:
            return f"Login error: {e}"

        finally:
            connection.close()

    return render_template("login.html")


# ==========================================
# 2. LOGOUT
# ==========================================

@app.route("/logout")
@login_required
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==========================================
# 3. USER DASHBOARD
# ==========================================

@app.route("/")
@login_required
def home():

    if session.get("account_role") == "admin":
        return redirect(url_for("admin_dashboard"))

    search = request.args.get("search", "").strip()
    status = request.args.get("status", "")
    severity = request.args.get("severity", "")

    user_id = session["user_id"]

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        query = """
            SELECT
                b.bug_id,
                b.title,
                b.status,
                b.severity,
                b.priority
            FROM bug b
            WHERE
                (
                    b.visibility = 'private'
                    AND b.created_by = %s
                )
                OR
                (
                    b.visibility = 'shared'
                    AND EXISTS (
                        SELECT 1
                        FROM project_members pm
                        WHERE pm.user_id = %s
                        AND pm.project_id = b.project_id
                    )
                )
        """

        values = [user_id, user_id]

        if search:
            query += " AND b.title ILIKE %s"
            values.append("%" + search + "%")

        if status:
            query += " AND b.status = %s"
            values.append(status)

        if severity:
            query += " AND b.severity = %s"
            values.append(severity)

        query += " ORDER BY b.bug_id"

        cursor.execute(query, tuple(values))
        bugs = cursor.fetchall()

        cursor.execute("""
            SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE status = 'Open'),
                COUNT(*) FILTER (WHERE status = 'Closed'),
                COUNT(*) FILTER (WHERE severity = 'Critical')
            FROM bug
            WHERE
                (
                    visibility = 'private'
                    AND created_by = %s
                )
                OR
                (
                    visibility = 'shared'
                    AND EXISTS (
                        SELECT 1
                        FROM project_members pm
                        WHERE pm.user_id = %s
                        AND pm.project_id = bug.project_id
                    )
                )
        """, (user_id, user_id))

        stats = cursor.fetchone()
        cursor.close()

        return render_template(
            "index.html",
            bugs=bugs,
            stats=stats,
            search=search,
            selected_status=status,
            selected_severity=severity,
            username=session["username"]
        )

    except Exception as e:
        return f"Error loading bugs: {e}"

    finally:
        connection.close()


# ==========================================
# 4. ADD BUG FORM
# ==========================================

@app.route("/add_bug")
@login_required
def add_bug():

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        if session.get("account_role") == "admin":

            cursor.execute("""
                SELECT project_id, project_name
                FROM project
                ORDER BY project_id
            """)

        else:

            cursor.execute("""
                SELECT p.project_id, p.project_name
                FROM project p
                JOIN project_members pm
                ON p.project_id = pm.project_id
                WHERE pm.user_id = %s
                ORDER BY p.project_id
            """, (session["user_id"],))

        projects = cursor.fetchall()

        cursor.execute("""
            SELECT developer_id, name
            FROM developer
            ORDER BY developer_id
        """)
        developers = cursor.fetchall()

        cursor.execute("""
            SELECT module_id, module_name
            FROM module
            ORDER BY module_id
        """)
        modules = cursor.fetchall()

        cursor.execute("""
            SELECT cause_id, cause_description
            FROM root_cause
            ORDER BY cause_id
        """)
        causes = cursor.fetchall()

        cursor.close()

        return render_template(
            "add_bug.html",
            projects=projects,
            developers=developers,
            modules=modules,
            causes=causes,
            account_role=session.get("account_role")
        )

    except Exception as e:
        return f"Error loading Add Bug form: {e}"

    finally:
        connection.close()


# ==========================================
# 5. SAVE BUG
# ==========================================

@app.route("/save_bug", methods=["POST"])
@login_required
def save_bug():

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "")

    project_id = request.form.get("project_id")
    developer_id = request.form.get("developer_id")
    module_id = request.form.get("module_id")
    cause_id = request.form.get("cause_id") or None

    status = request.form.get("status")
    severity = request.form.get("severity")
    priority = request.form.get("priority")

    visibility = request.form.get("visibility", "private")

    if not title or not project_id or not developer_id or not module_id:
        return "Please fill in all required fields."

    if visibility not in ("private", "shared"):
        return "Invalid bug visibility."

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        role = session.get("account_role")

        project_role = get_project_role(
            cursor,
            session["user_id"],
            project_id
        )

        if role != "admin" and project_role is None:
            connection.rollback()
            return "You are not a member of this project.", 403

        if (
            role != "admin"
            and project_role == "member"
            and visibility != "shared"
        ):
            connection.rollback()
            return "Project members can create shared bugs only.", 403

        cursor.execute("""
            INSERT INTO bug (
                project_id,
                developer_id,
                module_id,
                cause_id,
                title,
                description,
                status,
                severity,
                priority,
                created_by,
                visibility
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """, (
            int(project_id),
            developer_id,
            module_id,
            cause_id,
            title,
            description,
            status,
            severity,
            priority,
            session["user_id"],
            visibility
        ))

        connection.commit()
        cursor.close()

        if role == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("home"))

    except Exception as e:
        connection.rollback()
        return f"Error saving bug: {e}"

    finally:
        connection.close()


# ==========================================
# 6. EDIT BUG
# ==========================================

@app.route("/edit_bug/<int:bug_id>")
@login_required
def edit_bug(bug_id):

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        if not can_manage_bug(cursor, session["user_id"], bug_id):
            connection.rollback()
            return "You are not allowed to edit this bug.", 403

        cursor.execute("""
            SELECT
                bug_id,
                title,
                description,
                status,
                severity,
                priority
            FROM bug
            WHERE bug_id = %s
        """, (bug_id,))

        bug = cursor.fetchone()
        cursor.close()

        if bug is None:
            return "Bug record not found.", 404

        return render_template(
            "edit_bug.html",
            bug=bug,
            account_role=session.get("account_role")
        )

    except Exception as e:
        return f"Error loading bug: {e}"

    finally:
        connection.close()


# ==========================================
# 7. UPDATE BUG
# ==========================================

@app.route("/update_bug/<int:bug_id>", methods=["POST"])
@login_required
def update_bug(bug_id):

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "")
    status = request.form.get("status")
    severity = request.form.get("severity")
    priority = request.form.get("priority")

    if not title:
        return "Bug title is required."

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        if not can_manage_bug(cursor, session["user_id"], bug_id):
            connection.rollback()
            return "You are not allowed to edit this bug.", 403

        cursor.execute("""
            UPDATE bug
            SET title = %s,
                description = %s,
                status = %s,
                severity = %s,
                priority = %s
            WHERE bug_id = %s
        """, (
            title,
            description,
            status,
            severity,
            priority,
            bug_id
        ))

        connection.commit()
        cursor.close()

        if session.get("account_role") == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("home"))

    except Exception as e:
        connection.rollback()
        return f"Error updating bug: {e}"

    finally:
        connection.close()


# ==========================================
# 8. DELETE BUG
# ==========================================

@app.route("/delete_bug/<int:bug_id>", methods=["POST"])
@login_required
def delete_bug(bug_id):

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        if not can_manage_bug(cursor, session["user_id"], bug_id):
            connection.rollback()
            return "You are not allowed to delete this bug.", 403

        cursor.execute("""
            DELETE FROM bug
            WHERE bug_id = %s
        """, (bug_id,))

        if cursor.rowcount == 0:
            connection.rollback()
            return "Bug record not found.", 404

        connection.commit()
        cursor.close()

        if session.get("account_role") == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("home"))

    except Exception as e:
        connection.rollback()
        return f"Error deleting bug: {e}"

    finally:
        connection.close()


# ==========================================
# 9. ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        # Bug statistics
        cursor.execute("""
            SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE status = 'Open'),
                COUNT(*) FILTER (WHERE status = 'Closed'),
                COUNT(*) FILTER (WHERE severity = 'Critical')
            FROM bug
        """)

        bug_stats = cursor.fetchone()

        # User count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        # Project count
        cursor.execute("SELECT COUNT(*) FROM project")
        project_count = cursor.fetchone()[0]

        # All users
        cursor.execute("""
            SELECT user_id, username, email, account_role, is_active
            FROM users
            ORDER BY user_id
        """)

        users = cursor.fetchall()

        # All bugs including private bugs
        cursor.execute("""
            SELECT
                b.bug_id,
                b.title,
                b.status,
                b.severity,
                b.priority,
                b.visibility,
                u.username,
                p.project_name
            FROM bug b
            LEFT JOIN users u ON u.user_id = b.created_by
            LEFT JOIN project p ON p.project_id = b.project_id
            ORDER BY b.bug_id DESC
        """)

        bugs = cursor.fetchall()

        # All projects
        cursor.execute("""
            SELECT project_id, project_name
            FROM project
            ORDER BY project_id
        """)

        projects = cursor.fetchall()

        # Project memberships
        cursor.execute("""
            SELECT
                pm.user_id,
                u.username,
                pm.project_id,
                p.project_name,
                pm.role
            FROM project_members pm
            JOIN users u ON u.user_id = pm.user_id
            JOIN project p ON p.project_id = pm.project_id
            ORDER BY p.project_id, u.username
        """)

        memberships = cursor.fetchall()

        # Active users for membership dropdown
        cursor.execute("""
            SELECT user_id, username
            FROM users
            WHERE is_active = TRUE
            ORDER BY username
        """)

        active_users = cursor.fetchall()

        cursor.close()

        return render_template(
            "admin_dashboard.html",
            bug_stats=bug_stats,
            user_count=user_count,
            project_count=project_count,
            users=users,
            bugs=bugs,
            projects=projects,
            memberships=memberships,
            active_users=active_users,
            username=session["username"]
        )

    except Exception as e:
        return f"Error loading Admin Dashboard: {e}"

    finally:
        connection.close()


# ==========================================
# 10. CREATE USER ACCOUNT
# ==========================================

@app.route("/admin/users/create", methods=["POST"])
@admin_required
def create_user():

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not username or not email or not password:
        return "Username, email and password are required.", 400

    if len(password) < 8:
        return "Password must contain at least 8 characters.", 400

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO users (
                username,
                email,
                password_hash,
                account_role,
                is_active
            )
            VALUES (%s, %s, %s, 'user', TRUE)
        """, (
            username,
            email,
            generate_password_hash(password)
        ))

        connection.commit()
        cursor.close()

        return redirect(url_for("admin_dashboard"))

    except Exception as e:
        connection.rollback()
        return (
            "Could not create user. Check that username and email are unique. "
            + str(e)
        ), 400

    finally:
        connection.close()


# ==========================================
# 11. ACTIVATE / DEACTIVATE USER
# ==========================================

@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id):

    if user_id == session["user_id"]:
        return "You cannot deactivate your own Admin account.", 400

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE users
            SET is_active = NOT is_active
            WHERE user_id = %s
            AND account_role <> 'admin'
        """, (user_id,))

        if cursor.rowcount == 0:
            connection.rollback()
            return "User not found or Admin accounts cannot be changed here.", 404

        connection.commit()
        cursor.close()

        return redirect(url_for("admin_dashboard"))

    except Exception as e:
        connection.rollback()
        return f"Error updating account status: {e}"

    finally:
        connection.close()


# ==========================================
# 12. ADD / UPDATE PROJECT MEMBER
# ==========================================

@app.route("/admin/members/add", methods=["POST"])
@admin_required
def add_project_member():

    user_id = request.form.get("user_id", type=int)
    project_id = request.form.get("project_id", type=int)
    role = request.form.get("role", "")

    if not user_id or not project_id or role not in ("owner", "member"):
        return "Choose a user, project and valid project role.", 400

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT is_active
            FROM users
            WHERE user_id = %s
        """, (user_id,))

        target_user = cursor.fetchone()

        cursor.execute("""
            SELECT 1
            FROM project
            WHERE project_id = %s
        """, (project_id,))

        target_project = cursor.fetchone()

        if not target_user or not target_user[0] or not target_project:
            connection.rollback()
            return "Choose an active user and an existing project.", 400

        cursor.execute("""
            INSERT INTO project_members (
                user_id,
                project_id,
                role
            )
            VALUES (%s, %s, %s)

            ON CONFLICT (user_id, project_id)
            DO UPDATE SET role = EXCLUDED.role
        """, (user_id, project_id, role))

        connection.commit()
        cursor.close()

        return redirect(url_for("admin_dashboard"))

    except Exception as e:
        connection.rollback()
        return f"Could not add project member: {e}"

    finally:
        connection.close()


# ==========================================
# 13. REMOVE PROJECT MEMBER
# ==========================================

@app.route("/admin/members/remove", methods=["POST"])
@admin_required
def remove_project_member():

    user_id = request.form.get("user_id", type=int)
    project_id = request.form.get("project_id", type=int)

    if not user_id or not project_id:
        return "Invalid member or project.", 400

    connection = get_db_connection()

    if connection is None:
        return "Database connection failed."

    try:
        cursor = connection.cursor()

        cursor.execute("""
            DELETE FROM project_members
            WHERE user_id = %s
            AND project_id = %s
        """, (user_id, project_id))

        if cursor.rowcount == 0:
            connection.rollback()
            return "Project membership not found.", 404

        connection.commit()
        cursor.close()

        return redirect(url_for("admin_dashboard"))

    except Exception as e:
        connection.rollback()
        return f"Could not remove project member: {e}"

    finally:
        connection.close()


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
