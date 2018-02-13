# Browser Artifact Recovery Forensic Framework (BARFF)
# Author:
# Patrick Olsen - patrickolsen@sysforensics.org
# @patrickrolsen
# www.sysforensics.org

import datetime, time
import sys, getopt, os
import sqlite3

debug = 1
def dbg_print(msg):
    if debug == 1:
        print msg

#####Google Chrome######
class historyEntry:
    def __init__(self, visit_time, url):
        self.visit_time  = visit_time
        self.url         = url

class downloadsEntry:
    def __init__(self, start_time, url, full_path):
        self.start_time  = start_time
        self.url         = url
        self.full_path   = full_path

class countEntry:
    def __init__(self, url, visit_count, last_visit_time):
        self.url             = url
        self.visit_count     = visit_count
        self.last_visit_time = last_visit_time

class cookieEntry:
    def __init__(self, creation, expires, host_key, name, value, path, secure):
        self.creation       = creation
        self.expires        = expires
        self.host_key       = host_key
        self.name           = name
        self.value          = value
        self.path           = path
        self.secure         = secure

#####Mozilla Firefox#####
class mozbookmarksEntry:
    def __init__(self, dateAdded, title, url, visit_count):
        self.dateAdded   = dateAdded
        self.title       = title
        self.url         = url
        self.visit_count = visit_count

class mozcountEntry:
    def __init__(self, last_visit_date, url, visit_count):
        self.last_visit_date  = last_visit_date
        self.url              = url
        self.visit_count      = visit_count

class mozcookieEntry:
    def __init__(self, baseDomain, name, value, host, creationTime, expiry):
        self.baseDomain     = baseDomain
        self.name           = name
        self.value          = value
        self.host           = host
        self.creationTime   = creationTime
        self.expiry         = expiry

######Google Drive#######
class drive_cloudEntry:
    def __init__(self, filename, modified, created, doc_type, url, shared, checksum):
        self.filename    = filename
        self.modified    = modified
        self.created     = created
        self.doc_type    = doc_type
        self.url         = url
        self.shared      = shared
        self.checksum    = checksum

class drive_localEntry:
    def __init__(self, filename, modified, checksum):
        self.filename    = filename
        self.modified    = modified
        self.checksum    = checksum

#######SKYPE######
class skype_profileEntry:
    def __init__(self, skypename, fullname, about, country, city, emails):
        self.skypename                 = skypename
        self.fullname                  = fullname
        self.about                     = about
        self.country                   = country
        self.city                      = city
        self.emails                    = emails

class skype_messagesEntry:
    def __init__(self, friendlyname, author, from_dispname, body_xml, timestamp, dialog_partner):
        self.friendlyname   = friendlyname
        self.author         = author
        self.from_dispname  = from_dispname
        self.body_xml       = body_xml
        self.timestamp      = timestamp
        self.dialog_partner = dialog_partner

#######Evernote######
class enote_nbookEntry:
    def __init__(self, title, notebook, date_created, date_updated, source_url):
        self.title         = title
        self.notebook      = notebook
        self.date_created  = date_created
        self.date_updated  = date_updated
        self.source_url    = source_url

# All of the browser (Chrome, Firefox, etc.) will inherit from this browserCommon class.
class browserCommon:
    def __init__(self, profile_directory):
        self.profile_directory = profile_directory

    # dbpath is the sqlite3 database relative to profile_directory
    def get_conn_cursor(self, dbpath):
        db = os.path.join(self.profile_directory, dbpath)
        conn = sqlite3.connect(db)
        cursor = conn.cursor()

        return (conn, cursor)

    # Google Chrome History Database - Getting the history information
    def print_history(self, history_list):
        print "{}|{}".format("Visit Time", "URL")
        for histEnt in history_list:
            print "{0.visit_time}|{0.url}".format(histEnt)

    # Google Chrome History Database - Download information
    def print_downloads(self, download_list):
        #print "{}|{}|{}".format("Start Time", "URL", "Download Path")
        for downEnt in download_list:
            #print "{0.start_time}|{0.url}|{0.full_path}".format(downEnt)
            print ""
            print "Start Time:", downEnt.start_time
            print "Full Path:", downEnt.full_path
            print "URL:", downEnt.url

    # Google Chrome History - Visit counts
    def print_count(self, count_list):
        print "{}|{}|{}".format("Last Visited", "URL", "Visit Count")
        for countEnt in count_list:
            print "{0.last_visit_time}|{0.url}|{0.visit_count}".format(countEnt)

    # Google Chrome Cookies Database - Cookie information
    def print_cookie(self, cookie_list):
        print "{}|{}|{}|{}|{}|{}|{}"\
        .format("Created", "Expires", "Host Key", "Name", "Value", "Path", "Secure")
        for cookieEnt in cookie_list:
            print "{0.creation}|{0.expires}|{0.host_key}|{0.name}|{0.value}|{0.path}|{0.secure}"\
            .format(cookieEnt)

    # Mozilla Firefox Places Database - Bookmark information
    def print_mozbookmarks(self, mozbookmark_list):
        print "{}|{}|{}|{}".format("Data Added", "Title", "URL", "Visit Count")
        for mozbookEnt in mozbookmark_list:
            print "{0.dateAdded}|{0.title}|{0.url}|{0.visit_count}".format(mozbookEnt)

    # Mozilla Firefox Places Database - Visit Count
    def print_mozcount(self, mozcount_list):
        print "{}|{}|{}".format("Visit Date", "URL", "Visit Count")
        for mozcountEnt in mozcount_list:
            print "{0.last_visit_date}|{0.url}|{0.visit_count}".format(mozcountEnt)

    # Mozilla Firefox Places Database - Cookie
    def print_mozcookie(self, mozcookie_list):
        print "{}|{}|{}|{}|{}|{}"\
        .format("Domain", "Name", "Value", "Host", "Create", "Expire")
        for mozcookieEnt in mozcookie_list:
            print "{0.baseDomain}|{0.name}|{0.value}{0.host}|{0.creationTime}|{0.expiry}"\
            .format(mozcookieEnt)

    # Google Drive Snapshot Database - Cloud Entry info
    def print_drive_cloudentry(self, cloudentry_list):
        print "{}|{}|{}|{}|{}|{}|{}"\
        .format("Filename", "Modified", "Created","Document Type", "URL", "Shared", "MD5")
        for centryEnt in cloudentry_list:
            print "{0.filename}|{0.modified}|{0.created}|{0.doc_type}|{0.url}|{0.shared}|{0.checksum}"\
            .format(centryEnt)

    # Google Drive Snapshot Database - Local Entry info
    def print_drive_localentry(self, localentry_list):
        print "{}|{}|{}".format("Modified", "Filename", "MD5")
        for lentryEnt in localentry_list:
            print "{0.modified}|{0.filename}|{0.checksum}".format(lentryEnt)

    # Skype Main DB Parsing - User Profile
    def print_skypeprofile(self, skypeprofile_list):
        print "{}|{}|{}|{}|{}|{}"\
        .format("Skypename", "Fullname", "About", "Country", "City", "Email")
        for sprofileEnt in skypeprofile_list:
            print "{0.skypename}|{0.fullname}|{0.about}|{0.country}|{0.city}|{0.emails}"\
            .format(sprofileEnt)

    # Skype Main DB Parsing - Message Information
    def print_skypemessage(self, skypemessage_list):
        print "{}|{}|{}|{}|{}"\
        .format("Friendly Name", "Author", "From Display Name", "Timestamp", "Dialog Partner")
        for smessageEnt in skypemessage_list:
            #Im not currently printing the XML Body.  I'm working on ways to best approach this.
            print "{0.friendlyname}|{0.author}|{0.from_dispname}|{0.timestamp}|{0.dialog_partner}"\
            .format(smessageEnt)

    # Evernote <name>.ebx - Notes/Notebook Information
    def print_enotebook(self, enotebook_list):
        print "{}|{}|{}|{}|{}"\
        .format("Title", "Notebook", "Date Created", "Date Updated", "Source")
        for enbookEnt in enotebook_list:
            print "{0.title}|{0.notebook}|{0.date_created}|{0.date_updated}|{0.source_url}"\
            .format(enbookEnt)

# Chrome browser class
class Chrome(browserCommon):
    def __init__(self, profile_directory):
        browserCommon.__init__(self, profile_directory)

    # Google Chrome - History Information
    def get_history(self):
        res = []
        (conn, cursor) = self.get_conn_cursor("History")
        cursor.execute("SELECT datetime(visits.visit_time/1000000-11644473600,\'unixepoch\'), \
        urls.url FROM urls, visits WHERE urls.id = visits.url ORDER BY visits.visit_time DESC")
        for (visit_time, url) in cursor.fetchall():
            res.append(historyEntry(visit_time, url))
        return res

    # Google Chrome - Downloads information
    def get_downloads(self):
        res = []
        (conn, cursor) = self.get_conn_cursor("History")
        cursor.execute("SELECT datetime(downloads.start_time, \
        \'unixepoch\'), downloads.url, \
        downloads.full_path FROM downloads")
        for (start_time, url, full_path) in cursor.fetchall():
            res.append(downloadsEntry(start_time, url, full_path))
        return res

    # Google Chrome - Site Visit Count
    def get_sitecount(self):
        res = []
        (conn, cursor) = self.get_conn_cursor("History")
        # I added the > 0 here so you can filter it how you want.
        cursor.execute("SELECT url, visit_count, \
        datetime(last_visit_time/1000000-11644473600,\'unixepoch\') \
        AS \'last_visit_time\' FROM urls WHERE visit_count > 0 ORDER BY \
        visit_count COLLATE NOCASE DESC")
        for (url, visit_count, last_visit_time) in cursor.fetchall():
            res.append(countEntry(url, visit_count, last_visit_time))
        return res

    # Google Chrome - Cookies Information
    def get_cookie(self):
        res = []
        (conn, cursor) = self.get_conn_cursor("Cookies")
        cursor.execute("SELECT datetime(creation_utc/1000000-11644473600, \
        \'unixepoch\'), datetime(expires_utc/1000000-11644473600,\
        \'unixepoch\'), host_key, name, value, path, secure FROM \
        cookies ORDER BY cookies.expires_utc DESC")
        for (creation, expires, host_key, name, value, path, secure) in cursor.fetchall():
            res.append(cookieEntry(creation, expires, host_key, name, value, path, secure))
        return res

# Firefox browser class
class Firefox(browserCommon):
    def __init__(self, profile_directory):
        browserCommon.__init__(self, profile_directory)

    # Mozilla Firefox - Bookmark Information
    def get_mozbookmarks(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('places.sqlite')
        cursor.execute('SELECT datetime(moz_bookmarks.dateAdded/1000000, \
        \'unixepoch\'),moz_bookmarks.title,moz_places.url, moz_places.visit_count \
        FROM moz_bookmarks, moz_places WHERE moz_places.id = moz_bookmarks.fk \
        ORDER BY moz_bookmarks.dateAdded ASC')
        for (dateAdded, title, url, visit_count) in cursor.fetchall():
            res.append(mozbookmarksEntry(dateAdded, title, url, visit_count))
        return res

    # Mozilla Firefox - Visit Count
    def get_mozcount(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('places.sqlite')
        cursor.execute('SELECT datetime(last_visit_date/1000000, \
        \'unixepoch\'),url,visit_count FROM moz_places ORDER BY \
        visit_count DESC')
        for (last_visit_date, url, visit_count) in cursor.fetchall():
            res.append(mozcountEntry(last_visit_date, url, visit_count))
        return res

    # Mozilla Firefox - Cookies
    def get_mozcookie(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('cookies.sqlite')
        #cursor.execute('SELECT baseDomain, name, value, datetime(creationTime/1000000,\'unixepoch\'), \
        #datetime(expiry,\'unixepoch\') FROM moz_cookies')
        cursor.execute('SELECT baseDomain, name, value, host, datetime(creationTime/1000000, \'unixepoch\'), \
        datetime(expiry,\'unixepoch\') from moz_cookies')
        for (baseDomain, name, value, host, creationTime, expiry) in cursor.fetchall():
            res.append(mozcookieEntry(baseDomain, name, value, host, creationTime, expiry))
        return res

# Google Drive class
class Drive(browserCommon):
    def __init__(self, profile_directory):
        browserCommon.__init__(self, profile_directory)

    # Google Drive - Cloud Entry Table Information
    def get_cloudentry(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('snapshot.db')
        cursor.execute('SELECT filename, datetime(modified, \'unixepoch\'), \
        datetime(created, \'unixepoch\'), doc_type, shared, checksum, url \
        FROM cloud_entry')
        for (filename, modified, created, doc_type, url, shared, checksum) in cursor.fetchall():
            res.append(drive_cloudEntry(filename, modified, created, doc_type, url, shared, checksum))
        return res

    # Google Drive - Local Entry Table Information
    def get_localentry(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('snapshot.db')
        cursor.execute('SELECT filename, datetime(modified, \'unixepoch\'), \
        checksum FROM local_entry')
        for (filename, modified, checksum) in cursor.fetchall():
            res.append(drive_localEntry(filename, modified, checksum))
        return res

# Skype class
class Skype(browserCommon):
    def __init__(self, profile_directory):
        browserCommon.__init__(self, profile_directory)

    # Skype User Profile Information
    def get_skypeprofile(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('main.db')
        cursor.execute('SELECT skypename, fullname, about, country, city, \
        emails FROM Accounts')
        for (skypename, fullname, about, country, city, emails) in cursor.fetchall():
            res.append(skype_profileEntry(skypename, fullname, about, country, city, emails))
        return res

    # Skype Message Information
    def get_skypemessage(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('main.db')
        #NOTE: I'm pulling body_xml, but not currently printing it. I'm thinking of the best way to do this.
        #REF: http://code.google.com/p/log2timeline
        cursor.execute('SELECT Chats.friendlyname,Messages.author,Messages.from_dispname,Messages.body_xml, \
        datetime(Messages.timestamp,\'unixepoch\'),Messages.dialog_partner FROM Chats,Messages \
        WHERE Chats.name = Messages.chatname')
        for (friendlyname, author, from_dispname, body_xml, timestamp, dialog_partner) in cursor.fetchall():
            res.append(skype_messagesEntry(friendlyname, author, from_dispname, body_xml, timestamp, dialog_partner))
        return res

# Evernote class
class Evernote(browserCommon):
    def __init__(self, profile_directory):
        browserCommon.__init__(self, profile_directory)

    # Evernote Notebook Information collection
    def get_enotebook(self):
        res = []
        (conn, cursor) = self.get_conn_cursor('mrwh1t3.exb')
        cursor.execute('SELECT title, notebook, date_created, date_updated, source_url FROM note_attr')
        for (title, notebook, date_created, date_updated, source_url) in cursor.fetchall():
            res.append(enote_nbookEntry(title, notebook, date_created, date_updated, source_url))
        return res

# This is how we are able to specify the -b Chrome, -b Firefox, etc.
# This is the "Get" Browser Class
def get_browser_class(browser_type, profile_directory):
    ret = None
    browsers = {
        'chrome'   : Chrome,
        'chromium' : Chrome,
        'firefox'  : Firefox,
        'mozilla'  : Firefox,
        'drive'    : Drive,
        'skype'    : Skype,
        'evernote' : Evernote
    }
    if profile_directory and len(profile_directory) > 0:
        browser = browsers.get(browser_type.lower())
        if browser:
            ret = browser(profile_directory)
        else:
            dbg_print("Unsupported browse given: %s" % browser_type)
    else:
        dbg_print("Invalid profile_directory given.")

    return ret

# Command Line Arguements
def main():
    profile_directory = None
    browser_type      = None
    plugin            = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], \
        "h:d:b:p:",["help", "directory", "browser", "plugin"])
    except getopt.GetoptError:
        print ''
        print 'Browser Artifact Recovery Forensic Framework (BARFF)'
        print ''
        print 'barff.py "-d", "--directory" "-b", "--browser "-p", "--plugin"'
        print ''
        print 'Plugins supported:'
        print 'Google Chrome History:         -b Chrome   -p history'
        print 'Google Chrome Visited Count:   -b Chrome   -p count'
        print 'Google Chrome Cookies:         -b Chrome   -p cookie'
        print 'Google Chrome Downloads:       -b Chrome   -p downloads'
        print 'Firefox Bookmarks:             -b Firefox  -p mozbookmark'
        print 'Firefox Visit Count:           -b Firefox  -p mozcount'
        print 'Firefox Cookie:                -b Firefox  -p mozcookie'
        print 'Google Drive Cloud Entry:      -b Drive    -p cloudentry'
        print 'Google Drive Local Entry:      -b Drive    -p localentry'
        print 'Skype Main DB User Profile:    -b Skype    -p skypeprofile'
        print 'Skype Main DB Message Profile: -b Skype    -p skypemessage'
        print 'Evernote Notebook/Notes Info:  -b Evernote -p enotebook'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            sys.exit()
        elif opt in ("-d", "--directory"):
            profile_directory = arg
        elif opt in ("-b", "--browser"):
            browser_type = arg
        elif opt in ("-p", "--plugin"):
            plugin = arg

    if None in [profile_directory, browser_type, plugin]:
        dbg_print("Not all command line parameters specified. Remember: -b, -d, and -p")
        sys.exit(1)

    browser = get_browser_class(browser_type, profile_directory)
    actions = {
    'history'      : lambda b: b.print_history(b.get_history()),
    'downloads'    : lambda b: b.print_downloads(b.get_downloads()),
    'count'        : lambda b: b.print_count(b.get_sitecount()),
    'cookie'       : lambda b: b.print_cookie(b.get_cookie()),
    'mozbookmark'  : lambda b: b.print_mozbookmarks(b.get_mozbookmarks()),
    'mozcount'     : lambda b: b.print_mozcount(b.get_mozcount()),
    'mozcookie'    : lambda b: b.print_mozcookie(b.get_mozcookie()),
    'cloudentry'   : lambda b: b.print_drive_cloudentry(b.get_cloudentry()),
    'localentry'   : lambda b: b.print_drive_localentry(b.get_localentry()),
    'skypeprofile' : lambda b: b.print_skypeprofile(b.get_skypeprofile()),
    'skypemessage' : lambda b: b.print_skypemessage(b.get_skypemessage()),
    'enotebook'    : lambda b: b.print_enotebook(b.get_enotebook())
    }

    if browser == None:
        dbg_print("Invalid browser_type or profile_directory")

    actions[plugin](browser)

if __name__ == "__main__":
    main()