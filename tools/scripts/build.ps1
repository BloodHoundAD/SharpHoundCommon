nuget restore ..\..\src\CommonLib\CommonLib.csproj
dotnet build ..\..\src\CommonLib\CommonLib.csproj
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=json /p:CoverletOut=./coverage/ ..\..\test\unit\CommonLibTest.csproj
dotnet run --project ..\..\test\performance\CommonLibPerformance.csproj -c Release