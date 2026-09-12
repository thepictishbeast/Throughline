FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 ethtool nftables procps bash mount util-linux iputils-ping \
      autoconf automake libtool pkg-config gcc make libev-dev \
      tk xvfb imagemagick x11-apps xauth fonts-dejavu git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/coreemu/core.git /opt/core
WORKDIR /opt/core
# configure.ac hard-codes ./venv/bin/python and refuses to run without it,
# so the venv is part of the build, not a convenience.
RUN python -m venv --system-site-packages venv && \
    ./venv/bin/pip install --no-cache-dir grpcio==1.69.0 grpcio-tools==1.69.0 \
      protobuf==5.29.3 fabric==3.2.2 invoke==2.2.0 lxml==5.2.2 \
      netaddr==0.10.1 Mako==1.2.3 PyYAML==6.0.1 pillow==11.1.0 pyproj==3.6.1
# vnoded and vcmd: CORE's own C programs. The daemon will not start
# without them, so a fork owns this build too.
RUN ./bootstrap.sh && ./configure --prefix=/usr && make -j4 && make install
WORKDIR /opt/core/daemon
RUN /opt/core/venv/bin/python -m grpc_tools.protoc -I proto \
      --python_out=. --grpc_python_out=. proto/core/api/grpc/*.proto
# Its pyproject uses the poetry backend; an editable install would drag
# poetry-core in for no benefit here. PYTHONPATH runs it as-is.
ENV PYTHONPATH=/opt/core/daemon
COPY run.sh /run.sh
RUN chmod +x /run.sh
CMD ["/run.sh"]
