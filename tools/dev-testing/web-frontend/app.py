#!/usr/bin/env python3
"""
Sniper Web Frontend - View and sort hosts/services from PostgreSQL database
"""

import csv
import io
from functools import wraps
from flask import Flask, render_template, request, Response, flash, redirect, url_for, session
import psycopg2
import psycopg2.extras

from config import Config, get_connection_string, AUTH_USERNAME, AUTH_PASSWORD

app = Flask(__name__)
app.config.from_object(Config)


def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == AUTH_USERNAME and password == AUTH_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


def get_db_connection():
    """Create a database connection"""
    try:
        conn = psycopg2.connect(get_connection_string())
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        return None


def query_db(query, args=(), one=False, dict_cursor=True):
    """Execute a query and return results"""
    conn = get_db_connection()
    if not conn:
        return None if one else []

    try:
        if dict_cursor:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cur = conn.cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        conn.close()
        return (rv[0] if rv else None) if one else rv
    except psycopg2.Error as e:
        print(f"Query error: {e}")
        conn.close()
        return None if one else []


@app.route('/')
@login_required
def index():
    """Dashboard with statistics"""
    stats = {
        'hosts': 0,
        'services_open': 0,
        'vulns': 0
    }

    # Get counts
    result = query_db("SELECT COUNT(*) as count FROM hosts", one=True)
    if result:
        stats['hosts'] = result['count']

    result = query_db("SELECT COUNT(*) as count FROM services WHERE state = 'open'", one=True)
    if result:
        stats['services_open'] = result['count']

    result = query_db("SELECT COUNT(*) as count FROM vulns", one=True)
    if result:
        stats['vulns'] = result['count']

    # OS distribution
    os_distribution = query_db("""
        SELECT COALESCE(os_name, 'Unknown') as os_name, COUNT(*) as count
        FROM hosts
        GROUP BY os_name
        ORDER BY count DESC
        LIMIT 10
    """)

    # Top ports
    top_ports = query_db("""
        SELECT port, name, COUNT(*) as count
        FROM services
        WHERE state = 'open'
        GROUP BY port, name
        ORDER BY count DESC
        LIMIT 10
    """)

    return render_template('index.html',
                           stats=stats,
                           os_distribution=os_distribution,
                           top_ports=top_ports)


@app.route('/hosts')
@login_required
def hosts():
    """List all hosts with filtering"""
    # Build query based on filters
    query = """
        SELECT h.*,
               (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id AND s.state = 'open') as service_count
        FROM hosts h
        WHERE 1=1
    """
    params = []

    # Apply filters
    os_name = request.args.get('os_name')
    if os_name:
        query += " AND h.os_name = %s"
        params.append(os_name)

    purpose = request.args.get('purpose')
    if purpose:
        query += " AND h.purpose = %s"
        params.append(purpose)

    search = request.args.get('search')
    if search:
        query += " AND (h.address::text ILIKE %s OR h.name ILIKE %s)"
        params.extend([f'%{search}%', f'%{search}%'])

    query += " ORDER BY h.address"

    hosts = query_db(query, params)

    # Get filter options
    os_options = [r['os_name'] for r in query_db(
        "SELECT DISTINCT os_name FROM hosts WHERE os_name IS NOT NULL AND os_name != '' ORDER BY os_name"
    )]
    purpose_options = [r['purpose'] for r in query_db(
        "SELECT DISTINCT purpose FROM hosts WHERE purpose IS NOT NULL AND purpose != '' ORDER BY purpose"
    )]

    return render_template('hosts.html',
                           hosts=hosts,
                           os_options=os_options,
                           purpose_options=purpose_options)


@app.route('/hosts/<int:host_id>')
@login_required
def host_detail(host_id):
    """Show details for a single host"""
    host = query_db("SELECT * FROM hosts WHERE id = %s", [host_id], one=True)

    if not host:
        flash('Host not found', 'danger')
        return redirect(url_for('hosts'))

    services = query_db("""
        SELECT * FROM services
        WHERE host_id = %s
        ORDER BY port
    """, [host_id])

    vulns = query_db("""
        SELECT v.*, s.port,
               (SELECT string_agg(r.name, ', ')
                FROM vulns_refs vr
                JOIN refs r ON vr.ref_id = r.id
                WHERE vr.vuln_id = v.id) as refs
        FROM vulns v
        LEFT JOIN services s ON v.service_id = s.id
        WHERE v.host_id = %s
        ORDER BY v.name
    """, [host_id])

    return render_template('host_detail.html',
                           host=host,
                           services=services,
                           vulns=vulns)


@app.route('/services')
@login_required
def services():
    """List all services with filtering"""
    query = """
        SELECT s.*, h.address, h.id as host_id
        FROM services s
        JOIN hosts h ON s.host_id = h.id
        WHERE 1=1
    """
    params = []

    # Apply filters
    state = request.args.get('state')
    if state:
        query += " AND s.state = %s"
        params.append(state)

    proto = request.args.get('proto')
    if proto:
        query += " AND s.proto = %s"
        params.append(proto)

    port = request.args.get('port')
    if port:
        # Support comma-separated ports
        ports = [p.strip() for p in port.split(',') if p.strip().isdigit()]
        if ports:
            query += f" AND s.port IN ({','.join(['%s'] * len(ports))})"
            params.extend(ports)

    name = request.args.get('name')
    if name:
        query += " AND s.name = %s"
        params.append(name)

    search = request.args.get('search')
    if search:
        query += " AND (h.address::text ILIKE %s OR s.info ILIKE %s)"
        params.extend([f'%{search}%', f'%{search}%'])

    query += " ORDER BY h.address, s.port"

    services = query_db(query, params)

    # Get filter options
    service_options = [r['name'] for r in query_db(
        "SELECT DISTINCT name FROM services WHERE name IS NOT NULL AND name != '' ORDER BY name"
    )]

    return render_template('services.html',
                           services=services,
                           service_options=service_options)


@app.route('/vulns')
@login_required
def vulns():
    """List all vulnerabilities"""
    query = """
        SELECT v.*, h.address, h.name as hostname, h.id as host_id, s.port,
               (SELECT string_agg(r.name, ', ')
                FROM vulns_refs vr
                JOIN refs r ON vr.ref_id = r.id
                WHERE vr.vuln_id = v.id) as refs
        FROM vulns v
        JOIN hosts h ON v.host_id = h.id
        LEFT JOIN services s ON v.service_id = s.id
        WHERE 1=1
    """
    params = []

    search = request.args.get('search')
    if search:
        query += " AND (v.name ILIKE %s OR h.address::text ILIKE %s OR v.info ILIKE %s)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    ref = request.args.get('ref')
    if ref:
        query += """ AND v.id IN (
            SELECT vr.vuln_id FROM vulns_refs vr
            JOIN refs r ON vr.ref_id = r.id
            WHERE r.name ILIKE %s
        )"""
        params.append(f'%{ref}%')

    query += " ORDER BY h.address, v.name"

    vulns = query_db(query, params)

    return render_template('vulns.html', vulns=vulns)


@app.route('/export/hosts')
@login_required
def export_hosts():
    """Export hosts to CSV"""
    hosts = query_db("""
        SELECT h.address, h.name, h.os_name, h.os_flavor, h.purpose, h.mac, h.info, h.comments,
               (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id AND s.state = 'open') as open_services
        FROM hosts h
        ORDER BY h.address
    """)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Address', 'Hostname', 'OS Name', 'OS Flavor', 'Purpose', 'MAC', 'Info', 'Comments', 'Open Services'])

    for host in hosts:
        writer.writerow([
            host['address'], host['name'], host['os_name'], host['os_flavor'],
            host['purpose'], host['mac'], host['info'], host['comments'], host['open_services']
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=hosts.csv'}
    )


@app.route('/export/services')
@login_required
def export_services():
    """Export services to CSV"""
    services = query_db("""
        SELECT h.address, s.port, s.proto, s.name, s.state, s.info
        FROM services s
        JOIN hosts h ON s.host_id = h.id
        ORDER BY h.address, s.port
    """)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Host', 'Port', 'Protocol', 'Service', 'State', 'Banner'])

    for svc in services:
        writer.writerow([
            svc['address'], svc['port'], svc['proto'],
            svc['name'], svc['state'], svc['info']
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=services.csv'}
    )


@app.route('/export/vulns')
@login_required
def export_vulns():
    """Export vulnerabilities to CSV"""
    vulns = query_db("""
        SELECT h.address, h.name as hostname, s.port, v.name as vuln_name, v.info,
               (SELECT string_agg(r.name, ', ')
                FROM vulns_refs vr
                JOIN refs r ON vr.ref_id = r.id
                WHERE vr.vuln_id = v.id) as refs
        FROM vulns v
        JOIN hosts h ON v.host_id = h.id
        LEFT JOIN services s ON v.service_id = s.id
        ORDER BY h.address, v.name
    """)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Host', 'Hostname', 'Port', 'Vulnerability', 'References', 'Info'])

    for vuln in vulns:
        writer.writerow([
            vuln['address'], vuln['hostname'], vuln['port'],
            vuln['vuln_name'], vuln['refs'], vuln['info']
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=vulnerabilities.csv'}
    )


if __name__ == '__main__':
    print("Starting Sniper Web Frontend...")
    print("Access the application at: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True, use_debugger=False)
