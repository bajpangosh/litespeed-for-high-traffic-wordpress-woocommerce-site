#!/bin/bash

# OpenLiteSpeed + MariaDB + PHP + Redis + WordPress + Let's Encrypt SSL + System Cron Job Script
# Fully optimized for high-traffic WordPress sites

# Enable error handling
set -e
trap 'echo "Error occurred at line $LINENO. Exit code: $?"; exit 1' ERR

# Log file setup
LOG_FILE="/var/log/wordpress-install.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

# Color codes for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log_message() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check system requirements
check_system_requirements() {
    log_message "${YELLOW}Checking system requirements...${NC}"
    
    # Check CPU cores
    CPU_CORES=$(nproc)
    if [ "$CPU_CORES" -lt 2 ]; then
        log_message "${RED}ERROR: Minimum 2 CPU cores required. Found: $CPU_CORES cores${NC}"
        exit 1
    fi
    
    # Check RAM (minimum 2GB)
    TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM_MB" -lt 2048 ]; then
        log_message "${RED}ERROR: Minimum 2GB RAM required. Found: $(($TOTAL_RAM_MB/1024))GB${NC}"
        exit 1
    fi
    
    # Check available disk space (minimum 10GB)
    AVAILABLE_SPACE_KB=$(df -k / | awk 'NR==2 {print $4}')
    AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB/1024/1024))
    if [ "$AVAILABLE_SPACE_GB" -lt 10 ]; then
        log_message "${RED}ERROR: Minimum 10GB free disk space required. Found: ${AVAILABLE_SPACE_GB}GB${NC}"
        exit 1
    fi

    # Check if ports 80 and 443 are available
    if netstat -tuln | grep -q ":80 "; then
        log_message "${RED}ERROR: Port 80 is already in use. Please free up port 80 before continuing${NC}"
        exit 1
    fi
    if netstat -tuln | grep -q ":443 "; then
        log_message "${RED}ERROR: Port 443 is already in use. Please free up port 443 before continuing${NC}"
        exit 1
    fi

    log_message "${GREEN}System requirements check passed${NC}"
}

# Check Ubuntu version
check_ubuntu_version() {
    log_message "${YELLOW}Checking Ubuntu version...${NC}"
    
    # Check if it's a Linux system
    if [ "$(uname)" != "Linux" ]; then
        log_message "${RED}ERROR: This script only supports Linux (Ubuntu 22.04 LTS)${NC}"
        exit 1
    }
    
    # Check if it's Ubuntu
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" != "ubuntu" ]; then
            log_message "${RED}ERROR: This script only supports Ubuntu. Detected: $ID${NC}"
            exit 1
        fi
        
        # Check Ubuntu version
        if [ "$VERSION_ID" != "22.04" ]; then
            log_message "${RED}ERROR: This script only supports Ubuntu 22.04 LTS${NC}"
            log_message "${RED}Current version: $PRETTY_NAME${NC}"
            log_message "${YELLOW}Please use Ubuntu 22.04 LTS for optimal compatibility${NC}"
            exit 1
        fi
        
        # Check if it's LTS
        if ! echo "$VERSION" | grep -q LTS; then
            log_message "${RED}ERROR: This script only supports Ubuntu LTS versions${NC}"
            exit 1
        fi
    else
        log_message "${RED}ERROR: Cannot determine OS version${NC}"
        exit 1
    fi
    
    # Check if system is up to date
    if ! apt-get update >/dev/null 2>&1; then
        log_message "${RED}ERROR: Unable to update package list. Check your internet connection and apt sources${NC}"
        exit 1
    fi
    
    # Check for pending updates
    if [ "$(apt-get -s upgrade | grep -c ^Inst)" -ne 0 ]; then
        log_message "${YELLOW}WARNING: System has pending updates. It's recommended to update before proceeding${NC}"
        read -p "Would you like to update the system now? (yes/no): " choice
        if [[ "$choice" == "yes" ]]; then
            apt-get upgrade -y || {
                log_message "${RED}ERROR: System update failed${NC}"
                exit 1
            }
        fi
    fi
    
    log_message "${GREEN}Ubuntu 22.04 LTS verified. System is compatible${NC}"
}

# Check network connectivity
check_network() {
    log_message "${YELLOW}Checking network connectivity...${NC}"
    
    # Check internet connectivity
    if ! ping -c 1 google.com >/dev/null 2>&1; then
        log_message "${RED}ERROR: No internet connection detected${NC}"
        exit 1
    fi
    
    # Check DNS resolution
    if ! nslookup google.com >/dev/null 2>&1; then
        log_message "${RED}ERROR: DNS resolution failed${NC}"
        exit 1
    }
    
    # Check if required ports are accessible
    if ! nc -zw1 ports.ubuntu.com 80 >/dev/null 2>&1; then
        log_message "${RED}ERROR: Cannot access Ubuntu repositories${NC}"
        exit 1
    fi
    
    log_message "${GREEN}Network connectivity check passed${NC}"
}

# Ensure the script runs with root privileges
if [ "$EUID" -ne 0 ]; then
    log_message "${RED}ERROR: Please run this script as root or with sudo${NC}"
    exit 1
fi

# Function to check command success
check_command() {
    if [ $? -ne 0 ]; then
        log_message "${RED}ERROR: $1 failed${NC}"
        exit 1
    fi
}

# Function to display system information and recommendations
display_system_info() {
    log_message "${YELLOW}Gathering system information...${NC}"
    OS=$(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo "Unknown OS")
    CPU=$(lscpu | grep "Model name" | sed 's/Model name:[ \t]*//')
    RAM=$(free -h | awk '/^Mem:/{print $2}')
    CORES=$(nproc)
    DISK_SPACE=$(df -h / | awk 'NR==2 {print $4}')

    echo -e "\n====== System Information ======"
    echo "Operating System: $OS"
    echo "CPU: $CPU"
    echo "CPU Cores: $CORES"
    echo "Total RAM: $RAM"
    echo "Available Disk Space: $DISK_SPACE"
    echo -e "================================\n"

    # Check minimum requirements
    RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$RAM_MB" -lt 2048 ]; then
        log_message "${YELLOW}WARNING: System has less than 2GB RAM. This may impact performance${NC}"
    fi

    if [ "$CORES" -lt 2 ]; then
        log_message "${YELLOW}WARNING: System has less than 2 CPU cores. This may impact performance${NC}"
    fi

    # Provide recommendations based on system resources
    echo "Recommended Configuration for High-Traffic WordPress:"
    echo "- Ensure at least 2 CPU cores and 2GB RAM for optimal performance"
    echo "- For best results with caching and high concurrency, 4GB+ RAM and 4+ cores are recommended"
    echo "- PHP 8.1 or 8.2 for improved performance and security"
    echo "- MariaDB 10.6 or later for better query handling"
    echo "- Redis for object caching to reduce database load"
    echo -e "================================\n"

    # Confirm before proceeding
    read -p "Do you want to proceed with the installation? (yes/no): " choice
    if [[ "$choice" != "yes" ]]; then
        log_message "${RED}Installation aborted by user${NC}"
        exit 1
    fi
}

# Function to validate domain name
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        log_message "${RED}ERROR: Invalid domain name format${NC}"
        return 1
    fi
    return 0
}

# Function to validate email
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        log_message "${RED}ERROR: Invalid email format${NC}"
        return 1
    fi
    return 0
}

# Function to prompt for domain name
get_domain_name() {
    while true; do
        read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
        if validate_domain "$DOMAIN_NAME"; then
            break
        else
            echo "Please enter a valid domain name"
        fi
    done
}

# Function to prompt for email address for SSL
get_email_address() {
    while true; do
        read -p "Enter your email address for SSL notifications: " EMAIL_ADDRESS
        if validate_email "$EMAIL_ADDRESS"; then
            break
        else
            echo "Please enter a valid email address"
        fi
    done
}

# Function to prompt for PHP version
choose_php_version() {
    echo -e "\n${YELLOW}Select PHP version to install:${NC}"
    echo "1) PHP 8.1 (Stable, Recommended)"
    echo "2) PHP 8.2 (Latest)"
    read -p "Enter your choice (1 or 2): " php_choice

    case $php_choice in
        1) 
            PHP_VERSION="lsphp81"
            PHP_FULL_VERSION="8.1"
            ;;
        2) 
            PHP_VERSION="lsphp82"
            PHP_FULL_VERSION="8.2"
            ;;
        *) 
            log_message "${YELLOW}Invalid choice. Defaulting to PHP 8.1${NC}"
            PHP_VERSION="lsphp81"
            PHP_FULL_VERSION="8.1"
            ;;
    esac
    log_message "${GREEN}Selected PHP version: $PHP_FULL_VERSION${NC}"
}

# Install PHP for OpenLiteSpeed
install_php() {
    log_message "${YELLOW}Installing PHP $PHP_FULL_VERSION and essential modules...${NC}"
    
    # Install PHP and required modules
    apt install -y $PHP_VERSION \
        $PHP_VERSION-common \
        $PHP_VERSION-mysql \
        $PHP_VERSION-curl \
        $PHP_VERSION-gd \
        $PHP_VERSION-mbstring \
        $PHP_VERSION-xml \
        $PHP_VERSION-zip \
        $PHP_VERSION-intl \
        $PHP_VERSION-soap \
        $PHP_VERSION-xmlrpc \
        $PHP_VERSION-bcmath \
        $PHP_VERSION-imagick \
        $PHP_VERSION-redis \
        $PHP_VERSION-opcache \
        $PHP_VERSION-igbinary \
        $PHP_VERSION-msgpack || {
            log_message "${RED}Failed to install PHP packages${NC}"
            exit 1
        }
    
    # Create symbolic link
    ln -sf /usr/local/lsws/${PHP_VERSION}/bin/lsphp /usr/local/lsws/fcgi-bin/lsphp || {
        log_message "${RED}Failed to create PHP symbolic link${NC}"
        exit 1
    }

    # Configure PHP settings for optimal performance
    PHP_INI="/usr/local/lsws/${PHP_VERSION}/etc/php.ini"
    PHP_FPM_CONF="/usr/local/lsws/${PHP_VERSION}/etc/php-fpm.conf"
    
    log_message "${YELLOW}Configuring PHP for optimal performance...${NC}"
    
    # Backup original configurations
    cp "$PHP_INI" "${PHP_INI}.bak"
    if [ -f "$PHP_FPM_CONF" ]; then
        cp "$PHP_FPM_CONF" "${PHP_FPM_CONF}.bak"
    fi

    # Configure PHP.ini for high traffic
    sed -i 's/^max_execution_time.*/max_execution_time = 300/' "$PHP_INI"
    sed -i 's/^max_input_time.*/max_input_time = 300/' "$PHP_INI"
    sed -i 's/^memory_limit.*/memory_limit = 768M/' "$PHP_INI"
    sed -i 's/^post_max_size.*/post_max_size = 128M/' "$PHP_INI"
    sed -i 's/^upload_max_filesize.*/upload_max_filesize = 128M/' "$PHP_INI"
    sed -i 's/^max_input_vars.*/max_input_vars = 10000/' "$PHP_INI"
    sed -i 's/^max_file_uploads.*/max_file_uploads = 50/' "$PHP_INI"
    sed -i 's/^default_socket_timeout.*/default_socket_timeout = 60/' "$PHP_INI"
    sed -i 's/^;realpath_cache_size.*/realpath_cache_size = 4096k/' "$PHP_INI"
    sed -i 's/^;realpath_cache_ttl.*/realpath_cache_ttl = 120/' "$PHP_INI"
    
    # Configure OpCache for high traffic
    log_message "${YELLOW}Configuring PHP OpCache for high traffic...${NC}"
    sed -i 's/^;opcache.enable=.*/opcache.enable=1/' "$PHP_INI"
    sed -i 's/^;opcache.memory_consumption=.*/opcache.memory_consumption=512/' "$PHP_INI"
    sed -i 's/^;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=64/' "$PHP_INI"
    sed -i 's/^;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=50000/' "$PHP_INI"
    sed -i 's/^;opcache.revalidate_freq=.*/opcache.revalidate_freq=60/' "$PHP_INI"
    sed -i 's/^;opcache.save_comments=.*/opcache.save_comments=1/' "$PHP_INI"
    sed -i 's/^;opcache.fast_shutdown=.*/opcache.fast_shutdown=1/' "$PHP_INI"
    sed -i 's/^;opcache.enable_file_override=.*/opcache.enable_file_override=1/' "$PHP_INI"
    sed -i 's/^;opcache.validate_timestamps=.*/opcache.validate_timestamps=1/' "$PHP_INI"
    sed -i 's/^;opcache.max_wasted_percentage=.*/opcache.max_wasted_percentage=10/' "$PHP_INI"
    
    # Add custom optimizations for WordPress
    echo "
; WordPress High Traffic Optimizations
realpath_cache_size = 4096k
realpath_cache_ttl = 120
max_input_vars = 10000
max_input_nesting_level = 128
session.cookie_httponly = 1
session.use_strict_mode = 1
session.use_only_cookies = 1
session.gc_maxlifetime = 7200
session.gc_probability = 1
session.gc_divisor = 100
expose_php = Off

; Error Handling
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

; Performance Optimizations
zlib.output_compression = On
zlib.output_compression_level = 4
output_buffering = 4096
serialize_precision = -1
disable_functions = exec,shell_exec,system,passthru,popen
max_execution_time = 300
max_input_time = 300

; MySQL Connection Optimizations
mysql.allow_persistent = On
mysql.max_persistent = 100
mysql.connect_timeout = 60

; Security Headers
session.cookie_secure = 1
session.cookie_samesite = 'Strict'
" >> "$PHP_INI"

    # Configure PHP-FPM for high traffic
    if [ -f "$PHP_FPM_CONF" ]; then
        log_message "${YELLOW}Configuring PHP-FPM for high traffic...${NC}"
        
        # Calculate FPM settings based on available memory
        TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
        MAX_CHILDREN=$(( TOTAL_RAM_MB / 50 )) # Allocate ~50MB per child
        START_SERVERS=$(( MAX_CHILDREN / 4 ))
        MIN_SPARE_SERVERS=$START_SERVERS
        MAX_SPARE_SERVERS=$(( MAX_CHILDREN / 2 ))
        
        sed -i 's/^pm = .*/pm = dynamic/' "$PHP_FPM_CONF"
        sed -i "s/^pm.max_children = .*/pm.max_children = $MAX_CHILDREN/" "$PHP_FPM_CONF"
        sed -i "s/^pm.start_servers = .*/pm.start_servers = $START_SERVERS/" "$PHP_FPM_CONF"
        sed -i "s/^pm.min_spare_servers = .*/pm.min_spare_servers = $MIN_SPARE_SERVERS/" "$PHP_FPM_CONF"
        sed -i "s/^pm.max_spare_servers = .*/pm.max_spare_servers = $MAX_SPARE_SERVERS/" "$PHP_FPM_CONF"
        sed -i 's/^;pm.max_requests = .*/pm.max_requests = 1000/' "$PHP_FPM_CONF"
        sed -i 's/^;request_terminate_timeout = .*/request_terminate_timeout = 300/' "$PHP_FPM_CONF"
        sed -i 's/^;emergency_restart_threshold = .*/emergency_restart_threshold = 10/' "$PHP_FPM_CONF"
        sed -i 's/^;emergency_restart_interval = .*/emergency_restart_interval = 1m/' "$PHP_FPM_CONF"
        sed -i 's/^;process_control_timeout = .*/process_control_timeout = 10s/' "$PHP_FPM_CONF"
        
        # Add custom PHP-FPM optimizations
        echo "
; Custom PHP-FPM Optimizations
rlimit_files = 65535
rlimit_core = unlimited
catch_workers_output = yes
decorate_workers_output = no
" >> "$PHP_FPM_CONF"
    fi

    # Verify PHP installation
    if ! /usr/local/lsws/${PHP_VERSION}/bin/php -v >/dev/null 2>&1; then
        log_message "${RED}PHP installation verification failed${NC}"
        exit 1
    fi

    # Create PHP info file for testing
    PHP_TEST_DIR="/usr/local/lsws/$DOMAIN_NAME/html/php-test"
    mkdir -p "$PHP_TEST_DIR"
    echo "<?php phpinfo(); ?>" > "$PHP_TEST_DIR/info.php"
    chmod 644 "$PHP_TEST_DIR/info.php"

    log_message "${GREEN}PHP $PHP_FULL_VERSION installed and configured successfully${NC}"
    log_message "${YELLOW}PHP info available at: https://$DOMAIN_NAME/php-test/info.php${NC}"
    log_message "${YELLOW}Remember to remove php-test directory after verification${NC}"
}

# Install prerequisites
install_prerequisites() {
    log_message "${YELLOW}Installing prerequisites for Ubuntu 22.04...${NC}"
    
    # Add OpenLiteSpeed repository for Ubuntu 22.04
    wget -O - https://repo.litespeed.sh | bash || {
        log_message "${RED}Failed to add OpenLiteSpeed repository${NC}"
        exit 1
    }
    
    # Update package list
    apt update || {
        log_message "${RED}Failed to update package list${NC}"
        exit 1
    }
    
    # Install required packages for Ubuntu 22.04
    apt install -y wget curl gnupg2 software-properties-common dirmngr ca-certificates \
        apt-transport-https lsb-release unzip certbot python3-certbot-apache || {
        log_message "${RED}Failed to install prerequisites${NC}"
        exit 1
    }
}

# Install OpenLiteSpeed
install_ols() {
    log_message "${YELLOW}Installing OpenLiteSpeed...${NC}"
    
    if [ ! -d "/usr/local/lsws" ]; then
        # Install OpenLiteSpeed
        apt install -y openlitespeed || {
            log_message "${RED}Failed to install OpenLiteSpeed${NC}"
            exit 1
        }
        
        # Set default admin password
        ADMIN_PASS=$(openssl rand -base64 12)
        
        # Set root password and secure installation
        echo "admin:$(openssl passwd -apr1 $ADMIN_PASS)" > /usr/local/lsws/admin/conf/htpasswd || {
            log_message "${RED}Failed to set OpenLiteSpeed admin password${NC}"
            exit 1
        }
        
        log_message "${GREEN}OpenLiteSpeed admin credentials:${NC}"
        log_message "Username: admin"
        log_message "Password: $ADMIN_PASS"
        echo "Please save these credentials securely."
    else
        log_message "${YELLOW}OpenLiteSpeed already installed, skipping installation${NC}"
    fi
}

# Configure OpenLiteSpeed for high traffic
configure_ols_tuning() {
    log_message "${YELLOW}Configuring OpenLiteSpeed for high traffic...${NC}"
    
    OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"
    VHOST_CONF="/usr/local/lsws/conf/vhosts/$DOMAIN_NAME/vhconf.conf"
    
    # Backup original configuration
    cp "$OLS_CONF" "${OLS_CONF}.bak" || {
        log_message "${RED}Failed to backup OpenLiteSpeed configuration${NC}"
        exit 1
    }
    
    # Configure main settings
    sed -i 's/maxConnections.*$/maxConnections 10000/' "$OLS_CONF"
    sed -i 's/maxSSLConnections.*$/maxSSLConnections 10000/' "$OLS_CONF"
    sed -i 's/keepAliveTimeout.*$/keepAliveTimeout 5/' "$OLS_CONF"
    sed -i 's/maxKeepAliveReq.*$/maxKeepAliveReq 1000/' "$OLS_CONF"
    sed -i 's/smartKeepAlive.*$/smartKeepAlive 1/' "$OLS_CONF"
    sed -i 's/connTimeout.*$/connTimeout 300/' "$OLS_CONF"
    sed -i 's/maxReqURLLen.*$/maxReqURLLen 8192/' "$OLS_CONF"
    sed -i 's/maxReqHeaderSize.*$/maxReqHeaderSize 32768/' "$OLS_CONF"
    sed -i 's/maxReqBodySize.*$/maxReqBodySize 2047M/' "$OLS_CONF"
    
    # Enable GZIP compression
    echo "
enableGzip                1
gzipCompressLevel        6
compressibleTypes        text/*, application/x-javascript, application/javascript, application/xml, application/json, application/x-httpd-php
gzipMinFileSize          1k
gzipMaxFileSize          2M
" >> "$OLS_CONF"

    # Create and configure virtual host
    mkdir -p "/usr/local/lsws/conf/vhosts/$DOMAIN_NAME"
    cat > "$VHOST_CONF" << EOF
docRoot                   \$VH_ROOT/html/wordpress
enableGzip               1
enableIpGeo             1
cgroups                 1

index  {
  useServer               0
  indexFiles             index.php, index.html
}

errorlog \$VH_ROOT/logs/error.log {
  useServer               0
  logLevel               ERROR
  rollingSize            10M
}

accesslog \$VH_ROOT/logs/access.log {
  useServer               0
  logFormat              "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
  logHeaders             5
  rollingSize            10M
  keepDays               10
}

scripthandler  {
  add                     lsapi:$PHP_VERSION php
}

extprocessor $PHP_VERSION {
  type                    lsapi
  address                 uds://tmp/lshttpd/$PHP_VERSION.sock
  maxConns               35
  env                     PHP_LSAPI_CHILDREN=35
  initTimeout             60
  retryTimeout           0
  persistConn            1
  respBuffer             0
  autoStart              2
  path                   /usr/local/lsws/$PHP_VERSION/bin/lsphp
  memSoftLimit           2047M
  memHardLimit           2047M
  procSoftLimit          400
  procHardLimit          500
}

rewrite  {
  enable                  1
  rules                   <<<END_rules
rewrite ^(.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
  END_rules
}

vhssl  {
  keyFile                 /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
  certFile               /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
  certChain              1
  sslProtocol            24
  enableECDHE            1
  renegProtection        1
  sslSessionCache        1
  sslSessionTickets      1
  enableSpdy             15
  enableQuic             1
  enableStapling         1
  ocspRespMaxAge         86400
}
EOF

    # Create necessary directories
    mkdir -p "/usr/local/lsws/$DOMAIN_NAME/html/wordpress"
    mkdir -p "/usr/local/lsws/$DOMAIN_NAME/logs"
    
    # Set proper permissions
    chown -R nobody:nogroup "/usr/local/lsws/$DOMAIN_NAME"
    chmod -R 755 "/usr/local/lsws/$DOMAIN_NAME"
    
    log_message "${GREEN}OpenLiteSpeed configured for high traffic${NC}"
}

# Install MariaDB
install_mariadb() {
    log_message "${YELLOW}Installing MariaDB...${NC}"
    
    # Add MariaDB repository for Ubuntu 22.04
    curl -LsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash -s -- --mariadb-server-version=10.6 || {
        log_message "${RED}Failed to add MariaDB repository${NC}"
        exit 1
    }
    
    # Update package list
    apt update || {
        log_message "${RED}Failed to update package list${NC}"
        exit 1
    }
    
    # Install MariaDB
    apt install -y mariadb-server mariadb-client || {
        log_message "${RED}Failed to install MariaDB${NC}"
        exit 1
    }
    
    # Secure MariaDB installation
    DB_ROOT_PASS=$(openssl rand -base64 24)
    
    # Set root password and secure installation
    mysql -e "SET PASSWORD FOR root@localhost = PASSWORD('${DB_ROOT_PASS}');" || {
        log_message "${RED}Failed to set MariaDB root password${NC}"
        exit 1
    }
    
    mysql -e "DELETE FROM mysql.user WHERE User='';" || {
        log_message "${RED}Failed to remove anonymous users${NC}"
        exit 1
    }
    
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" || {
        log_message "${RED}Failed to remove remote root access${NC}"
        exit 1
    }
    
    mysql -e "DROP DATABASE IF EXISTS test;" || {
        log_message "${RED}Failed to remove test database${NC}"
        exit 1
    }
    
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || {
        log_message "${RED}Failed to remove test database privileges${NC}"
        exit 1
    }
    
    mysql -e "FLUSH PRIVILEGES;" || {
        log_message "${RED}Failed to flush privileges${NC}"
        exit 1
    }
    
    log_message "${GREEN}MariaDB root password: $DB_ROOT_PASS${NC}"
    echo "Please save this password securely."
    
    # Create WordPress database and user
    WP_DB_NAME="wordpress"
    WP_DB_USER="wpuser"
    WP_DB_PASS=$(openssl rand -base64 24)
    
    mysql -uroot -p"${DB_ROOT_PASS}" -e "CREATE DATABASE ${WP_DB_NAME};" || {
        log_message "${RED}Failed to create WordPress database${NC}"
        exit 1
    }
    
    mysql -uroot -p"${DB_ROOT_PASS}" -e "CREATE USER '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';" || {
        log_message "${RED}Failed to create WordPress database user${NC}"
        exit 1
    }
    
    mysql -uroot -p"${DB_ROOT_PASS}" -e "GRANT ALL PRIVILEGES ON ${WP_DB_NAME}.* TO '${WP_DB_USER}'@'localhost';" || {
        log_message "${RED}Failed to grant privileges to WordPress database user${NC}"
        exit 1
    }
    
    mysql -uroot -p"${DB_ROOT_PASS}" -e "FLUSH PRIVILEGES;" || {
        log_message "${RED}Failed to flush privileges${NC}"
        exit 1
    }
    
    log_message "${GREEN}WordPress database created successfully${NC}"
    log_message "Database Name: $WP_DB_NAME"
    log_message "Database User: $WP_DB_USER"
    log_message "Database Password: $WP_DB_PASS"
    echo "Please save these credentials securely."
}

# Optimize MariaDB for high traffic
optimize_mariadb() {
    log_message "${YELLOW}Optimizing MariaDB for high traffic...${NC}"
    
    # Calculate buffer pool size (50% of total RAM for dedicated servers)
    TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    BUFFER_POOL_SIZE=$(( TOTAL_RAM_MB / 2 ))
    
    # Calculate max connections based on RAM
    MAX_CONNECTIONS=$(( TOTAL_RAM_MB / 10 )) # Allocate ~10MB per connection
    if [ $MAX_CONNECTIONS -lt 100 ]; then
        MAX_CONNECTIONS=100
    elif [ $MAX_CONNECTIONS -gt 2000 ]; then
        MAX_CONNECTIONS=2000
    fi
    
    # Calculate thread pool size based on CPU cores
    CPU_CORES=$(nproc)
    THREAD_POOL_SIZE=$(( CPU_CORES * 2 ))
    
    # Backup original configuration
    MARIADB_CONF="/etc/mysql/mariadb.conf.d/50-server.cnf"
    cp "$MARIADB_CONF" "${MARIADB_CONF}.bak" || {
        log_message "${RED}Failed to backup MariaDB configuration${NC}"
        exit 1
    }
    
    # Create optimized configuration
    cat > "$MARIADB_CONF" << EOF
[mysqld]
# Basic Settings
user                    = mysql
pid-file                = /run/mysqld/mysqld.pid
socket                  = /run/mysqld/mysqld.sock
port                    = 3306
basedir                 = /usr
datadir                 = /var/lib/mysql
tmpdir                  = /tmp
lc-messages-dir         = /usr/share/mysql
bind-address            = 127.0.0.1

# Connection Settings
max_connections         = ${MAX_CONNECTIONS}
max_allowed_packet      = 268435456
connect_timeout         = 10
wait_timeout           = 600
max_allowed_packet     = 64M
thread_cache_size      = 128
thread_stack           = 192K
interactive_timeout    = 300
thread_handling        = pool-of-threads
thread_pool_size       = ${THREAD_POOL_SIZE}
thread_pool_max_threads = 2000

# InnoDB Settings
default-storage-engine  = InnoDB
innodb_buffer_pool_size = ${BUFFER_POOL_SIZE}M
innodb_buffer_pool_instances = ${CPU_CORES}
innodb_file_per_table   = 1
innodb_flush_log_at_trx_commit = 2
innodb_flush_method     = O_DIRECT
innodb_log_buffer_size  = 16M
innodb_log_file_size    = 256M
innodb_write_io_threads = ${CPU_CORES}
innodb_read_io_threads  = ${CPU_CORES}
innodb_io_capacity      = 2000
innodb_io_capacity_max  = 4000
innodb_buffer_pool_load_at_startup = 1
innodb_buffer_pool_dump_at_shutdown = 1
innodb_lru_scan_depth   = 256
innodb_page_cleaners    = ${CPU_CORES}
innodb_open_files       = 10000
innodb_purge_threads    = 4

# MyISAM Settings
key_buffer_size         = 32M
myisam_recover_options  = FORCE,BACKUP
myisam_sort_buffer_size = 64M

# Query Cache Settings
query_cache_type        = 1
query_cache_size        = 128M
query_cache_limit       = 2M
query_cache_min_res_unit = 2K

# Table Settings
table_open_cache        = 4000
table_definition_cache  = 2048
table_open_cache_instances = 16

# Search Settings
ft_min_word_len        = 3
ft_boolean_syntax      = ' |-><()~*:""&^'

# Temp Tables
tmp_table_size         = 256M
max_heap_table_size    = 256M

# Networking
max_allowed_packet     = 64M
interactive_timeout    = 300
wait_timeout          = 600

# Buffer Settings
join_buffer_size       = 4M
sort_buffer_size       = 4M
read_buffer_size       = 3M
read_rnd_buffer_size   = 4M
aria_pagecache_buffer_size = 64M

# Binlog Settings
expire_logs_days       = 7
sync_binlog           = 0
log_bin               = /var/log/mysql/mysql-bin.log
log_bin_index         = /var/log/mysql/mysql-bin.log.index
max_binlog_size       = 100M
binlog_cache_size     = 2M
binlog_format         = ROW

# Logging
slow_query_log        = 1
slow_query_log_file   = /var/log/mysql/mariadb-slow.log
long_query_time       = 2
log_error            = /var/log/mysql/error.log

# Security
local_infile          = 0
symbolic_links        = 0

# Performance Schema
performance_schema = ON
performance_schema_consumer_events_statements_history_long = ON

# Other Settings
character-set-server  = utf8mb4
collation-server      = utf8mb4_unicode_ci
transaction_isolation = READ-COMMITTED
EOF

    # Create directory for binary logs if it doesn't exist
    mkdir -p /var/log/mysql
    chown mysql:mysql /var/log/mysql
    
    # Restart MariaDB
    systemctl restart mariadb || {
        log_message "${RED}Failed to restart MariaDB${NC}"
        exit 1
    }
    
    # Verify optimization
    if ! mysql -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size';" > /dev/null 2>&1; then
        log_message "${RED}MariaDB optimization verification failed${NC}"
        exit 1
    fi
    
    log_message "${GREEN}MariaDB optimized successfully${NC}"
    log_message "Buffer Pool Size: ${BUFFER_POOL_SIZE}M"
    log_message "Max Connections: ${MAX_CONNECTIONS}"
    log_message "Thread Pool Size: ${THREAD_POOL_SIZE}"
}

# Install Redis
install_redis() {
    log_message "${YELLOW}Installing Redis...${NC}"
    
    # Install Redis server
    apt install -y redis-server || {
        log_message "${RED}Failed to install Redis${NC}"
        exit 1
    }
    
    # Backup original Redis configuration
    cp /etc/redis/redis.conf /etc/redis/redis.conf.bak || {
        log_message "${RED}Failed to backup Redis configuration${NC}"
        exit 1
    }
    
    # Configure Redis for better performance
    sed -i 's/^# maxmemory .*/maxmemory 512mb/' /etc/redis/redis.conf
    sed -i 's/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
    sed -i 's/^# maxclients .*/maxclients 10000/' /etc/redis/redis.conf
    sed -i 's/^tcp-keepalive .*/tcp-keepalive 300/' /etc/redis/redis.conf
    
    # Add additional optimizations
    echo "
# Performance Optimizations
activerehashing yes
rdbcompression yes
rdbchecksum yes
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes
" >> /etc/redis/redis.conf
    
    # Restart Redis
    systemctl restart redis-server || {
        log_message "${RED}Failed to restart Redis${NC}"
        exit 1
    }
    
    # Enable Redis to start on boot
    systemctl enable redis-server || {
        log_message "${RED}Failed to enable Redis${NC}"
        exit 1
    }
    
    log_message "${GREEN}Redis installed and configured successfully${NC}"
}

# Configure WordPress with optimizations
configure_wordpress_wpconfig() {
    log_message "${YELLOW}Configuring WordPress with optimizations...${NC}"
    
    # Download WordPress
    cd /usr/local/lsws/$DOMAIN_NAME/html || {
        log_message "${RED}Failed to change directory${NC}"
        exit 1
    }
    
    wget https://wordpress.org/latest.tar.gz || {
        log_message "${RED}Failed to download WordPress${NC}"
        exit 1
    }
    
    tar xzf latest.tar.gz || {
        log_message "${RED}Failed to extract WordPress${NC}"
        exit 1
    }
    
    mv wordpress/* . || {
        log_message "${RED}Failed to move WordPress files${NC}"
        exit 1
    }
    
    rm -rf wordpress latest.tar.gz
    
    # Generate WordPress salts
    SALTS=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
    
    # Create optimized wp-config.php
    cat > wp-config.php << EOF
<?php
/** Database Settings */
define('DB_NAME', '$WP_DB_NAME');
define('DB_USER', '$WP_DB_USER');
define('DB_PASSWORD', '$WP_DB_PASS');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

/** Authentication Unique Keys and Salts */
$SALTS

/** Database Table prefix */
\$table_prefix = 'wp_';

/** WordPress Memory Limits */
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');

/** WordPress Cache */
define('WP_CACHE', true);
define('ENABLE_CACHE', true);

/** Redis Object Cache */
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_REDIS_TIMEOUT', 1);
define('WP_REDIS_READ_TIMEOUT', 1);
define('WP_REDIS_DATABASE', 0);
define('WP_REDIS_PREFIX', '${DOMAIN_NAME}_');

/** Performance Optimizations */
define('WP_POST_REVISIONS', 10);
define('EMPTY_TRASH_DAYS', 7);
define('WP_CRON_LOCK_TIMEOUT', 120);
define('DISABLE_WP_CRON', true);          // We'll use system cron instead
define('WP_CACHE_KEY_SALT', '${DOMAIN_NAME}');
define('WP_HOME', 'https://${DOMAIN_NAME}');
define('WP_SITEURL', 'https://${DOMAIN_NAME}');

/** Media Optimizations */
define('MEDIA_TRASH', true);
define('IMAGE_EDIT_OVERWRITE', true);
define('CONCATENATE_SCRIPTS', false);      // Better handled by LiteSpeed Cache

/** Security Enhancements */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', false);      // Set to true after installing necessary plugins
define('FORCE_SSL_ADMIN', true);
define('WP_AUTO_UPDATE_CORE', 'minor');
define('AUTOMATIC_UPDATER_DISABLED', false);
define('WP_DISABLE_FATAL_ERROR_HANDLER', false);

/** Debug Settings - Change based on environment */
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
define('SCRIPT_DEBUG', false);
define('SAVEQUERIES', false);

/** WordPress Database Optimizations */
define('ALTERNATE_WP_CRON', true);
define('WP_ALLOW_REPAIR', false);

/** LiteSpeed Cache Settings */
define('LITESPEED_ALLOWED', true);
define('LITESPEED_ON', true);
define('LITESPEED_ADMIN', true);
define('LITESPEED_ADMIN_IP', '');

/** WordPress Content Directory */
define('WP_CONTENT_DIR', __DIR__ . '/wp-content');
define('WP_CONTENT_URL', 'https://${DOMAIN_NAME}/wp-content');

/** Block External HTTP Requests - Uncomment if needed */
// define('WP_HTTP_BLOCK_EXTERNAL', true);
// define('WP_ACCESSIBLE_HOSTS', 'api.wordpress.org,*.github.com');

/** Multisite Settings - Uncomment if needed */
// define('WP_ALLOW_MULTISITE', false);
// define('MULTISITE', false);

/** Absolute path to the WordPress directory */
if ( !defined('ABSPATH') )
    define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files */
require_once(ABSPATH . 'wp-settings.php');
EOF

    # Set proper permissions
    chown -R nobody:nogroup /usr/local/lsws/$DOMAIN_NAME/html
    find /usr/local/lsws/$DOMAIN_NAME/html -type d -exec chmod 755 {} \;
    find /usr/local/lsws/$DOMAIN_NAME/html -type f -exec chmod 644 {} \;
    
    # Create uploads directory with proper permissions
    mkdir -p /usr/local/lsws/$DOMAIN_NAME/html/wp-content/uploads
    chmod 755 /usr/local/lsws/$DOMAIN_NAME/html/wp-content/uploads
    chown -R nobody:nogroup /usr/local/lsws/$DOMAIN_NAME/html/wp-content/uploads
    
    # Create cache directory
    mkdir -p /usr/local/lsws/$DOMAIN_NAME/html/wp-content/cache
    chmod 755 /usr/local/lsws/$DOMAIN_NAME/html/wp-content/cache
    chown -R nobody:nogroup /usr/local/lsws/$DOMAIN_NAME/html/wp-content/cache
    
    # Install WP-CLI
    if [ ! -f "/usr/local/bin/wp" ]; then
        curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar || {
            log_message "${RED}Failed to download WP-CLI${NC}"
            exit 1
        }
        chmod +x wp-cli.phar
        mv wp-cli.phar /usr/local/bin/wp
    fi
    
    # Install and configure essential plugins using WP-CLI
    sudo -u nobody wp core install --url="https://${DOMAIN_NAME}" --title="WordPress Site" --admin_user="admin" --admin_password="$(openssl rand -base64 12)" --admin_email="${EMAIL_ADDRESS}" --skip-email --path=/usr/local/lsws/$DOMAIN_NAME/html/
    
    # Install essential plugins
    sudo -u nobody wp plugin install litespeed-cache redis-cache wp-mail-smtp --activate --path=/usr/local/lsws/$DOMAIN_NAME/html/
    
    # Configure LiteSpeed Cache plugin
    sudo -u nobody wp litespeed-option set cache-browser true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set cache-mobile true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set css_minify true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set js_minify true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set optm-css_comb true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set optm-js_comb true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set optm-html_min true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    sudo -u nobody wp litespeed-option set optm-qs_rm true --path=/usr/local/lsws/$DOMAIN_NAME/html/
    
    # Enable Redis object cache
    sudo -u nobody wp redis enable --path=/usr/local/lsws/$DOMAIN_NAME/html/
    
    log_message "${GREEN}WordPress configured successfully with optimizations${NC}"
    log_message "${YELLOW}Please save the WordPress admin credentials shown above${NC}"
}

# Install SSL
install_ssl() {
    log_message "${YELLOW}Installing SSL...${NC}"
    
    # Install Certbot
    apt install -y certbot python3-certbot-apache || {
        log_message "${RED}Failed to install Certbot${NC}"
        exit 1
    }
    
    # Obtain SSL certificate
    certbot certonly --webroot --webroot-path=/usr/local/lsws/$DOMAIN_NAME/html --email ${EMAIL_ADDRESS} --agree-tos --non-interactive --expand --domains -d $DOMAIN_NAME || {
        log_message "${RED}Failed to obtain SSL certificate${NC}"
        exit 1
    }
    
    # Configure SSL
    cat > /usr/local/lsws/conf/vhosts/$DOMAIN_NAME/vhconf.conf << EOF
vhssl  {
  keyFile                 /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
  certFile               /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
  certChain              1
  sslProtocol            24
  enableECDHE            1
  renegProtection        1
  sslSessionCache        1
  sslSessionTickets      1
  enableSpdy             15
  enableQuic             1
  enableStapling         1
  ocspRespMaxAge         86400
}
EOF
    
    log_message "${GREEN}SSL installed and configured successfully${NC}"
}

# Configure system cron
configure_system_cron() {
    log_message "${YELLOW}Configuring system cron...${NC}"
    
    # Create cron job for Certbot
    cat > /etc/cron.d/certbot << EOF
0 */12 * * * root test -x /usr/bin/certbot -a \! -d /run/systemd/system && perl -e 'sleep int(rand(3600))' && certbot -q renew --webroot --webroot-path=/usr/local/lsws/$DOMAIN_NAME/html --email ${EMAIL_ADDRESS} --agree-tos --non-interactive
EOF
    
    # Create cron job for WP-CLI
    cat > /etc/cron.d/wpcli << EOF
0 0 * * * nobody /usr/local/bin/wp --path=/usr/local/lsws/$DOMAIN_NAME/html/ --url=https://${DOMAIN_NAME} --allow-root cache flush
0 0 * * * nobody /usr/local/bin/wp --path=/usr/local/lsws/$DOMAIN_NAME/html/ --url=https://${DOMAIN_NAME} --allow-root db optimize
EOF
    
    log_message "${GREEN}System cron configured successfully${NC}"
}

# Main function with backup functionality
main() {
    # Check system requirements first
    check_system_requirements || { log_message "${RED}System requirements check failed${NC}"; exit 1; }
    
    # Check Ubuntu version
    check_ubuntu_version || { log_message "${RED}Ubuntu version check failed${NC}"; exit 1; }
    
    # Check network connectivity
    check_network || { log_message "${RED}Network connectivity check failed${NC}"; exit 1; }
    
    # Create backup directory
    BACKUP_DIR="/root/wordpress_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Start installation with logging
    log_message "${GREEN}Starting WordPress installation...${NC}"
    
    display_system_info
    get_domain_name
    get_email_address
    choose_php_version
    
    # Backup existing configurations if any
    if [ -d "/usr/local/lsws" ]; then
        log_message "${YELLOW}Backing up existing OpenLiteSpeed configuration...${NC}"
        cp -r /usr/local/lsws/conf "$BACKUP_DIR/lsws_conf_backup"
    fi
    
    if [ -f "/etc/mysql/mariadb.conf.d/50-server.cnf" ]; then
        log_message "${YELLOW}Backing up existing MariaDB configuration...${NC}"
        cp /etc/mysql/mariadb.conf.d/50-server.cnf "$BACKUP_DIR/mariadb_conf_backup"
    fi
    
    # Installation steps with error handling
    install_prerequisites || { log_message "${RED}Failed to install prerequisites${NC}"; exit 1; }
    install_ols || { log_message "${RED}Failed to install OpenLiteSpeed${NC}"; exit 1; }
    configure_ols_tuning || { log_message "${RED}Failed to configure OpenLiteSpeed${NC}"; exit 1; }
    install_php || { log_message "${RED}Failed to install PHP${NC}"; exit 1; }
    install_redis || { log_message "${RED}Failed to install Redis${NC}"; exit 1; }
    install_mariadb || { log_message "${RED}Failed to install MariaDB${NC}"; exit 1; }
    optimize_mariadb || { log_message "${RED}Failed to optimize MariaDB${NC}"; exit 1; }
    configure_wordpress_wpconfig || { log_message "${RED}Failed to configure WordPress${NC}"; exit 1; }
    install_ssl || { log_message "${RED}Failed to install SSL${NC}"; exit 1; }
    configure_system_cron || { log_message "${RED}Failed to configure cron${NC}"; exit 1; }
    
    systemctl restart lsws || { log_message "${RED}Failed to restart OpenLiteSpeed${NC}"; exit 1; }

    log_message "${GREEN}Installation completed successfully!${NC}"
    echo "WordPress with SSL, caching, and high-performance optimizations has been successfully installed."
    echo "Visit your site at https://$DOMAIN_NAME to complete the WordPress setup."
    echo "OpenLiteSpeed WebAdmin is accessible at https://<your_server_ip>:7080"
    echo "Installation log is available at: $LOG_FILE"
    echo "Configuration backups are stored in: $BACKUP_DIR"
}

check_system_requirements
check_ubuntu_version
check_network
main
