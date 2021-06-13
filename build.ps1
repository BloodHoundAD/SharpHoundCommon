# NOTE: These steps are now taken care of by the github actions found in .github/workflows and remain here for local testing and dev

#dependencies

## docfx: documentation generation 
# choco install docfx -y 

## act-cli: local testing of github actions
# choco install act-cli -y

### reportgenerator: output convertor for unit test coverage from .json to .html
# dotnet tool install -g dotnet-reportgenerator-globaltool

# restore app dependencies
nuget restore src\CommonLib\SharpHoundCommonLib.csproj

# build app. commented out since the test step below does the same thing.
# dotnet build src\CommonLib\SharpHoundCommonLib.csproj

# run tests
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=json /p:CoverletOutput=build\coverage.json test\unit\CommonLibTest.csproj

# generate test report from coverage.json. place directly in the docs folder to prevent copying a full static site needlessly
reportgenerator "-reports:test\unit\build\coverage.json" "-targetdir:docs\coverage" -reporttypes:HTML

# performance tests are not implemented but this command will run the basic DotnetBenchmark example
# dotnet run --project test\performance\CommonLibPerformance.csproj -c Release

# build docs 
# docfx

# serve docs: to test documentation locally combines a build and local web server step into one call
docfx --serve

# use act: requires docker
# act -s GITHUB_TOKEN=[insert token or leave blank for secure input]