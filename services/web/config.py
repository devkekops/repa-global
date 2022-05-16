from os.path import join, dirname, realpath
import os

SECRET_KEY = b'test'
#SQLALCHEMY_DATABASE_URI = 'sqlite:///repa.db'
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'repaUploadFiles/')

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = "redis://redis:6379/0"
    QUEUES = ["default"]
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_SSL = False
    MAIL_USE_TLS = True
    MAIL_USERNAME = ''
    MAIL_PASSWORD = ''
    MAIL_DEFAULT_SENDER = ''

AAPTPATH = '/Users/username/Library/Android/sdk/build-tools/30.0.3/aapt'
#print(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'apk', 'ipa'}

NSANDROIDURI = 'http://schemas.android.com/apk/res/android'
NSCENTRY = b'android:networkSecurityConfig="@xml/network_security_config"'
TRUSTANCHORS = b'trust-anchors'
CLEARTEXTTRAFFICPERMITTED = b'cleartextTrafficPermitted'
DISABLESAFEBROWSING = b'<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false"/>'
NSCPATH = "/res/xml/network_security_config.xml"
NSAPPTRANSPORTSECURITY = 'NSAppTransportSecurity'
NSALLOWSARBITRARYLOADS = 'NSAllowsArbitraryLoads'
NSALLOWSARBITRARYLOADSFORMEDIA = 'NSAllowsArbitraryLoadsForMedia'
NSALLOWSARBITRARYLOADSINWEBCONTENT = 'NSAllowsArbitraryLoadsInWebContent'
NSALLOWSLOCALNETWORKING = 'NSAllowsLocalNetworking'
NSEXCEPTIONDOMAINS = 'NSExceptionDomains'

EXTSLIST = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.bmp', '.webp', '.bmp', '.eot', '.otf', '.ttf', '.woff', '.woff2', '.so', '.proto', '.zip']

HTTPURLSBINARY = b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
HTTPURLS = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
WSURLSBINARY = b'ws[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
WSURLS = 'ws[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
ANDROIDBLACKLISTURLSBINARY = [b'http://schemas.android.com', b'http://www.apache.org', b'http://www.w3.org', b'http://schema.org',
                 b'http://www.obj-sys.com', b'http://ns.adobe.com', b'http://xml.org', b'http://xmlpull.org', b'http://xml.apache.org',
                 b'http://java.sun.com/', b'http://www.apple.com/DTDs', b'https://developer.android.com', b'https://developers.google.com/']
ANDROIDBLACKLISTURLS = ['http://schemas.android.com', 'http://www.apache.org', 'http://www.w3.org', 'http://schema.org',
                 'http://www.obj-sys.com', 'http://ns.adobe.com', 'http://xml.org', 'http://xmlpull.org', 'http://xml.apache.org',
                 'http://java.sun.com/', 'http://www.apple.com/DTDs', 'https://developer.android.com', 'https://developers.google.com/']
IOSBLACKLISTURLS = [b'http://www.apple.com', b'http://ocsp.apple.com', b'http://crl.apple.com', b'http://ocsp.comodoca.com', b'http://ns.adobe.com',
                    b'http://www.apache.org', b'http://www.w3.org', b'http://itunes', b'http://www.webrtc.org']
#QALINKS = ['qa', 'dev', 'test']
QALINKS = ['stag']
BASICAUTH = rb'^(.+?\/\/)(.+?):(.+?)@(.+)$'

PASSWORDBINARY = b'password'
PASSWORD = 'password'
PRIVATEKEYBINARY = b'-----BEGIN (?:EC|PGP|DSA|RSA|OPENSSH)? ?PRIVATE KEY ?(?:BLOCK)?-----'
PRIVATEKEY = '-----BEGIN (?:EC|PGP|DSA|RSA|OPENSSH)? ?PRIVATE KEY ?(?:BLOCK)?-----'
FCMSERVERKEYBINARY = rb'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
FCMSERVERKEY = r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
LEGACYFCMSERVERKEYBINARY = rb'AIzaSy[0-9A-Za-z_-]{33}'
LEGACYFCMSERVERKEY = r'AIzaSy[0-9A-Za-z_-]{33}'

SHOULDOVERRIDEURLLOADINGBINARY = b'shouldOverrideUrlLoading'
SHOULDOVERRIDEURLLOADING = 'shouldOverrideUrlLoading' #https://developer.android.com/reference/android/webkit/WebViewClient#shouldOverrideUrlLoading(android.webkit.WebView,%20android.webkit.WebResourceRequest)
SETALLOWFILEACCESSBINARY = b'setAllowFileAccess'
SETALLOWFILEACCESS = 'setAllowFileAccess'
SETJAVASCRIPTENABLEDBINARY = b'setJavaScriptEnabled'
SETJAVASCRIPTENABLED = 'setJavaScriptEnabled'

ANDROIDBINARYSEARCHOFF = False
thread = None
NS = "/test"

CHECKSINFO = {'NSC CustomTrustedCAs': {'tag': 'network', 'severity': 'Normal', 'info': 'Additional trust anchors in Network Security Config:\n<a target="_blank" href = "https://developer.android.com/training/articles/security-config#manifest">Add a Network Security Configuration file</a>\n<a target="_blank" href="https://developer.android.com/training/articles/security-config#ConfigCustom">Configure a custom CA</a>'},
              'NSC CleartextTraffic': {'tag': 'network', 'severity': 'Normal', 'info': 'Allow using the unencrypted HTTP protocol instead of HTTPS in Network Security Config:\n<a target="_blank" href = "https://developer.android.com/training/articles/security-config#manifest">Add a Network Security Configuration file</a>\n<a target="_blank" href = "https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted">Opt out of cleartext traffic</a>'},

              'Exported Activities': {'tag': 'components', 'severity': ' Info', 'info': 'Exported Activities can be accessed by external components or apps'},
              'Exported Receivers': {'tag': 'components', 'severity': 'Info', 'info': 'Exported Receivers can be accessed by external components or apps'},
              'Exported Services': {'tag': 'components', 'severity': 'Info', 'info': 'Exported Services can be accessed by external components or apps'},
              'Exported Providers': {'tag': 'components', 'severity': 'Info', 'info': 'Exported Providers can be accessed by external components or apps'},

              'NS Allows Arbitrary Loads': {'tag': 'network', 'severity': 'Normal', 'info': 'Disable ATS restrictions globally excepts for individual domains specified under NSExceptionDomains'},
              'NS Allows Arbitrary Loads For Media': {'tag': 'network', 'severity': 'Normal', 'info': 'Disable all ATS restrictions for media loaded through the AV Foundations framework'},
              'NS Allows Arbitrary Loads In Web Content': {'tag': 'network', 'severity': 'Normal', 'info': 'Disable ATS restrictions for all the connections made from web views'},
              'NS Allows Local Networking': {'tag': 'network', 'severity': 'Normal', 'info': 'Allow connection to unqualified domain names and .local domains'},
              'NS Exception Domains': {'tag': 'network', 'severity': 'Normal', 'info': 'NS Exception Domains'},

              'Http Insecure URLs': {'tag': 'urls', 'severity': 'Minor', 'info': 'Http URLs starts with http://'},
              'Http QA URLs': {'tag': 'urls', 'severity': 'Minor', 'info': 'Http URLs contains "qa", "test", "dev" strings'},
              'WS Insecure URLs': {'tag': 'urls', 'severity': 'Minor', 'info': 'WebSocket URLs starts with ws://'},
              'WS QA URLs': {'tag': 'urls', 'severity': 'Minor', 'info': 'WebSocket URLs contains "qa", "test", "dev" strings'},
              'Basic Auth URLs': {'tag': 'urls', 'severity': 'Major', 'info': 'basic auth'},

              'Private Keys': {'tag': 'keys', 'severity': 'Major', 'info': 'Asymmetric Private Keys - RSA, OPENSSH, EC, PGP, DSA'},
              'FCM Server Key': {'tag': 'keys', 'severity': 'Major', 'info': 'Authorization key for FCM SDK: see <a target="blank" href="https://abss.me/posts/fcm-takeover/">Firebase Cloud Messaging Service Takeover</a>'}, #example: AAAAODDc_Do:APA91bG5kQSzauxg1GSrq3eot5GUPyfouZ5KZObtBUpdM0xoxWGCulSPK1FIKan3IIBK-YlrkOcXkIo0kv7NlUFSOV54Qdy21z9czkFBoe6dMxBEEKAAD8KlC3LYuDugRdrMXJr1ggsL
              'Legacy FCM Server Key': {'tag': 'keys', 'severity': 'Major', 'info': 'Legacy Authorization key for FCM SDK: see <a target="blank" href="https://abss.me/posts/fcm-takeover/">Firebase Cloud Messaging Service Takeover</a>'}, #example: AIzaSyDIw1n6tfz8_ANZVXJLRuBQrX-7culIFHM
              'API Keys': {'tag': 'keys', 'severity': 'Major', 'info': 'api keys'},

              'Disabled SafeBrowsing': {'tag': 'webview', 'severity': 'Normal', 'info': 'EnableSafeBrowsing set to "false" in manifest allow open potentially unsafe websites in all WebViews:\n<a target="_blank" href = "https://developer.android.com/guide/webapps/managing-webview#safe-browsing">Google Safe Browsing Service</a>'},
              'shouldOverrideUrlLoadings': {'tag': 'webview', 'severity': 'Info', 'info': 'Allow open 3rd party links in WebView instead of browser:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebViewClient#shouldOverrideUrlLoading(android.webkit.WebView,%20android.webkit.WebResourceRequest)">shouldOverrideUrlLoading</a>'},
              'setJavaScriptEnabled': {'tag': 'webview', 'severity': 'Info', 'info': 'Tells the WebView to enable JavaScript execution (disabled by default): <a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean)">setJavascriptEnabled</a>'},
              'setAllowFileAccess': {'tag': 'webview', 'severity': 'Info', 'info': 'Enables or disables file access (on device file system) within WebView (enabled by default): <a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean)">setAllowFileAccess</a>'}
              }

DEFAULTANDROIDCHECKS = [{'name': 'NSC CustomTrustedCAs'},
                        {'name': 'NSC CleartextTraffic'},
                        {'name': 'Disabled SafeBrowsing'},
                        {'name': 'Exported Activities'},
                        {'name': 'Exported Receivers'},
                        {'name': 'Exported Services'},
                        {'name': 'Exported Providers'},
                        {'name': 'Http Insecure URLs'},
                        {'name': 'Http QA URLs'},
                        {'name': 'WS Insecure URLs'},
                        {'name': 'WS QA URLs'},
                        {'name': 'Basic Auth URLs', 'pattern': BASICAUTH},
                        {'name': 'Private Keys', 'pattern': PRIVATEKEY if ANDROIDBINARYSEARCHOFF else PRIVATEKEYBINARY},
                        {'name': 'FCM Server Key', 'pattern': FCMSERVERKEY if ANDROIDBINARYSEARCHOFF else FCMSERVERKEYBINARY},
                        {'name': 'Legacy FCM Server Key', 'pattern': LEGACYFCMSERVERKEY if ANDROIDBINARYSEARCHOFF else LEGACYFCMSERVERKEYBINARY},
                        {'name': 'shouldOverrideUrlLoadings', 'pattern': SHOULDOVERRIDEURLLOADING if ANDROIDBINARYSEARCHOFF else SHOULDOVERRIDEURLLOADINGBINARY},
                        {'name': 'setJavaScriptEnabled', 'pattern': SETJAVASCRIPTENABLED if ANDROIDBINARYSEARCHOFF else SETJAVASCRIPTENABLEDBINARY},
                        {'name': 'setAllowFileAccess', 'pattern': SETALLOWFILEACCESS if ANDROIDBINARYSEARCHOFF else SETALLOWFILEACCESSBINARY}
                ]

DEFAULTIOSCHECKS = [{'name': 'NS Allows Arbitrary Loads'},
                    {'name': 'NS Allows Arbitrary Loads For Media'},
                    {'name': 'NS Allows Arbitrary Loads In Web Content'},
                    {'name': 'NS Allows Local Networking'},
                    {'name': 'NS Exception Domains'},
                    {'name': 'Http Insecure URLs'},
                    {'name': 'Http QA URLs'},
                    {'name': 'WS Insecure URLs'},
                    {'name': 'WS QA URLs'},
                    {'name': 'Basic Auth URLs', 'pattern': BASICAUTH},
                    {'name': 'Private Keys', 'pattern': PRIVATEKEYBINARY},
                    {'name': 'FCM Server Key', 'pattern': FCMSERVERKEYBINARY},
                    {'name': 'Legacy FCM Server Key', 'pattern': LEGACYFCMSERVERKEYBINARY}
                ]

ANDROID = "android"
IOS = "ios"

ANDROIDHTTPINSECURELINKSCHECKINDEX = 7
ANDROIDHTTPQALINKSCHECKINDEX = 8
IOSHTTPINSECURELINKSCHECKINDEX = 5
IOSHTTPQALINKSCHECKINDEX = 6

ANDROIDWSINSECURELINKSCHECKINDEX = 9
ANDROIDWSQALINKSCHECKINDEX = 10
IOSWSINSECURELINKSCHECKINDEX = 7
IOSWSQALINKSCHECKINDEX = 8

ANDROIDSTARTLEVEL = 30
ANDROIDFINISHLEVEL = 100
IOSSTARTLEVEL = 10
IOSFINISHLEVEL = 100
