FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# All FirmAE dependencies (from install.sh) + QEMU + network tools
RUN apt-get update && apt-get install -y \
    # QEMU
    qemu-system-arm qemu-system-mips qemu-system-x86 qemu-user-static qemu-utils \
    # FirmAE core
    busybox-static bash-static fakeroot sudo git curl wget tar bc ruby \
    python3 python3-pip python3-psycopg2 python3-magic python3-bs4 \
    # Database
    postgresql postgresql-client libpq-dev \
    # FirmAE runtime
    dmsetup kpartx netcat-openbsd nmap snmp fdisk \
    uml-utilities util-linux vlan \
    # Extraction (full set from install.sh)
    libmagic1 mtd-utils gzip bzip2 cpio lzop lzma squashfs-tools \
    unzip p7zip p7zip-full arj lhasa cabextract sleuthkit \
    srecord zlib1g-dev liblzma-dev liblzo2-dev \
    # Network tools
    net-tools iproute2 iputils-ping iptables bridge-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir psycopg2-binary coloredlogs python-magic

# Install binwalk (required by FirmAE extractor)
RUN wget -q https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.tar.gz \
    && tar -xf v2.3.4.tar.gz \
    && cd binwalk-2.3.4 \
    && python3 setup.py install \
    && cd / && rm -rf /v2.3.4.tar.gz /binwalk-2.3.4

# Clone FirmAE (recursive for submodules)
RUN git clone --recursive --depth 1 https://github.com/pr0v3rbs/FirmAE.git /opt/FirmAE \
    && cp /opt/FirmAE/core/unstuff /usr/local/bin/ 2>/dev/null || true \
    && chmod +x /opt/FirmAE/run.sh \
    && cd /opt/FirmAE && ./download.sh

# Initialize PostgreSQL for FirmAE
RUN service postgresql start \
    && su - postgres -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" \
    && su - postgres -c "createdb -O firmadyne firmware" \
    && su - postgres -c "psql -d firmware < /opt/FirmAE/database/schema" \
    && service postgresql stop

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
