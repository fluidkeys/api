#!/bin/bash -eux

install_extra_ppas() {
  apt-key add /vagrant/vagrant/postgres_pgp_ACCC4CF8.asc
  echo 'deb http://apt.postgresql.org/pub/repos/apt/ bionic-pgdg main' > /etc/apt/sources.list.d/postgres.list
}

update_package_index() {
    sudo apt-get update
}

install_required_packages() {
    sudo apt-get install -y \
	ack-grep \
        dos2unix \
	firejail \
	git \
	htop \
	make \
	nfs-common \
	run-one \
	sqlite3 \
	tree \
	unzip \
	whois \
	zip
}

configure_ack() {
    sudo dpkg-divert --local --divert /usr/bin/ack --rename --add /usr/bin/ack-grep
}

install_symlinks() {
    ln -sf /vagrant/vagrant/bashrc /home/vagrant/.bashrc
}

atomic_download() {
    URL=$1
    DEST=$2

    TMP="$(tempfile)"

    wget -qO "${TMP}" "${URL}" && mv "${TMP}" "${DEST}"
}

install_postgresql_10() {
  # if postgres 9.5 is installed from system, remove it
  apt-get remove -y postgresql-9.5
  apt-get install -y postgresql-10 libpq-dev

  sed -i 's/port = 5433/port = 5432/g' /etc/postgresql/10/main/postgresql.conf
  sudo service postgresql restart
}

install_golang_1_10_5() {
    GO_TARBALL=/tmp/download/go1.10.5.linux-amd64.tar.gz
    GO_URL=https://dl.google.com/go/go1.10.5.linux-amd64.tar.gz

    if [ ! -f "${GO_TARBALL}" ]; then
	atomic_download "${GO_URL}" "${GO_TARBALL}"
    fi

    mkdir -p /opt/go
    # tarball paths start go/...
    tar --directory /opt --extract -f "${GO_TARBALL}"

    ln -sf /vagrant/vagrant/etc/profile.d/golang.sh /etc/profile.d/golang.sh
}

install_realize_go_package() {
    run_as_vagrant "go get github.com/oxequa/realize"
}

create_postgresql_database_and_user() {
    # We make a user and a database both called vagrant, then the vagrant
    # username will automatically access that database.
    CREATE_USER="createuser --superuser vagrant"
    CREATE_DATABASE="createdb --owner vagrant vagrant"

    # Run as postgres user, it has permission to do this
    su -c "${CREATE_USER}" postgres || true
    su -c "${CREATE_DATABASE}" postgres || true

    echo "ALTER USER vagrant WITH ENCRYPTED PASSWORD 'password';" |su -c psql postgres
}

migrate_database() {
  run_as_vagrant "make migrate"
}

run_as_vagrant() {
  su vagrant bash -l -c "$1"
}


install_symlinks
install_extra_ppas
update_package_index
install_required_packages
install_postgresql_10
install_golang_1_10_5
create_postgresql_database_and_user
install_realize_go_package
migrate_database

set +x
echo
echo "All done!"
echo
