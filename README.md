# LiteSpeed WordPress Panel

A modern web panel for managing WordPress sites on OpenLiteSpeed server, optimized for high traffic.

## Features

- WordPress Site Management
- Server Performance Monitoring
- Cache Control (LiteSpeed & Redis)
- SSL Certificate Management
- Database Optimization
- Security Management
- Backup & Restore
- System Updates

## Requirements

- Ubuntu 22.04 LTS
- OpenLiteSpeed
- PHP 7.4 or higher
- MariaDB 10.6 or higher
- Redis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/litespeed-for-high-traffic-wordpress-woocommerce-site.git
```

2. Make the installation script executable:
```bash
chmod +x install.sh
chmod +x install-panel.sh
```

3. Run the installation:
```bash
sudo ./install.sh
sudo ./install-panel.sh
```

4. Access the panel:
```
https://your-server-ip:7080/panel
```

Default login:
- Username: admin
- Password: your_secure_password (change this in includes/auth.php)

## Directory Structure

```
.
├── install.sh              # Main installation script
├── install-panel.sh        # Panel installation script
├── panel/
│   ├── assets/            # CSS, JS, and images
│   ├── includes/          # PHP includes
│   ├── templates/         # HTML templates
│   └── api/              # API endpoints
└── README.md
```

## Features

### Server Management
- WordPress site creation/deletion
- SSL certificate management
- Cache management
- Database optimization

### Performance Monitoring
- Server load
- Memory usage
- Disk usage
- Cache status

### Security
- SSL management
- Access control
- Password protection
- Security scanning

### Site Management
- Create new WordPress sites
- Manage existing sites
- Backup/restore
- Updates management

### Cache Control
- LiteSpeed Cache management
- Redis cache status
- Cache purge options
- Cache statistics

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository.
