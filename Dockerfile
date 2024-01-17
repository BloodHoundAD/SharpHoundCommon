FROM mono:6.12.0

# Install .NET SDK
ENV DOTNET_VERSION=5.0

RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin -Channel $DOTNET_VERSION -InstallDir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
    
WORKDIR /SharpHoundCommon

CMD [ "dotnet", "build" ]

## Build Docker image (one time):
# docker build -t sharphoundcommon-build . --no-cache

## Build solution (every time):
# docker run --rm -v "$(pwd):/SharpHoundCommon" sharphoundcommon-build
