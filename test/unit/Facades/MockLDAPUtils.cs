using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace CommonLibTest.Facades
{
    public class MockLDAPUtils : ILDAPUtils
    {
        private readonly Forest _forest;
        public MockLDAPUtils()
        {
            _forest = MockableForest.Construct("FOREST.LOCAL");
        }
        
        public void SetLDAPConfig(LDAPConfig config)
        {
            throw new System.NotImplementedException();
        }

        public string[] GetUserGlobalCatalogMatches(string name)
        {
            throw new System.NotImplementedException();
        }

        public TypedPrincipal ResolveIDAndType(string id, string domain)
        {
            var principal = id switch
            {
                "S-1-5-21-3130019616-2776909439-2417379446-512" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-512", Label.Group),
                "E32A6AC7-083B-4DD7-ACFF-6D9C2B1AFAF5" => new TypedPrincipal("E32A6AC7-083B-4DD7-ACFF-6D9C2B1AFAF5",
                    Label.Container),
                "S-1-5-21-3130019616-2776909439-2417379446-519" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-519", Label.Group),
                "S-1-5-32-544" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-544", Label.Group),
                "93A4A8AE-7F22-4F97-AEA3-FF6533CDFEC6" => new TypedPrincipal("93A4A8AE-7F22-4F97-AEA3-FF6533CDFEC6",
                    Label.Container),
                "AECCADF5-B229-4707-A8B2-DD9DAF463B86" => new TypedPrincipal("AECCADF5-B229-4707-A8B2-DD9DAF463B86",
                    Label.Container),
                "FAC7BD64-9E8F-44FA-9249-E882195C1D32" => new TypedPrincipal("FAC7BD64-9E8F-44FA-9249-E882195C1D32",
                    Label.Container),
                "E5A8401B-1A13-4CC3-BEFB-44A34FB3C501" => new TypedPrincipal("E5A8401B-1A13-4CC3-BEFB-44A34FB3C501",
                    Label.Container),
                "9559A62C-9385-4F40-9157-AC955FA2D24A" => new TypedPrincipal("9559A62C-9385-4F40-9157-AC955FA2D24A",
                    Label.Container),
                "EA4D7175-503B-4B66-9546-186F17EBFE91" => new TypedPrincipal("EA4D7175-503B-4B66-9546-186F17EBFE91",
                    Label.Container),
                "880F537C-5090-46E5-B226-A551ED0A835A" => new TypedPrincipal("880F537C-5090-46E5-B226-A551ED0A835A",
                    Label.Container),
                "955C6AE9-47A2-44AE-A5E5-EA2CADA05D4F" => new TypedPrincipal("955C6AE9-47A2-44AE-A5E5-EA2CADA05D4F",
                    Label.Container),
                "7763CFD7-53F7-4BC4-B5C9-8C6F8C013D51" => new TypedPrincipal("7763CFD7-53F7-4BC4-B5C9-8C6F8C013D51",
                    Label.Container),
                "080E4ACF-C934-462C-811D-410AF68B2E17" => new TypedPrincipal("080E4ACF-C934-462C-811D-410AF68B2E17",
                    Label.Container),
                "2312DA09-3DD4-4E89-9D14-8175DDD665B2" => new TypedPrincipal("2312DA09-3DD4-4E89-9D14-8175DDD665B2",
                    Label.Container),
                "79C939F1-9BED-4501-AD3E-EB38AE793FB4" => new TypedPrincipal("79C939F1-9BED-4501-AD3E-EB38AE793FB4",
                    Label.Container),
                "0BEB60AE-CB5D-4968-BF30-822BBA67EEFE" => new TypedPrincipal("0BEB60AE-CB5D-4968-BF30-822BBA67EEFE",
                    Label.Container),
                "D08D86BF-795F-42B6-8FF8-1378C9F84B2A" => new TypedPrincipal("D08D86BF-795F-42B6-8FF8-1378C9F84B2A",
                    Label.Container),
                "3C61C57B-B98F-45C3-A577-CAB70F4363C5" => new TypedPrincipal("3C61C57B-B98F-45C3-A577-CAB70F4363C5",
                    Label.Container),
                "E59739C0-FE8E-4667-AA5D-7564AADFB2B6" => new TypedPrincipal("E59739C0-FE8E-4667-AA5D-7564AADFB2B6",
                    Label.Container),
                "A293D1D5-B301-4C92-AAAB-4468BF6624DF" => new TypedPrincipal("A293D1D5-B301-4C92-AAAB-4468BF6624DF",
                    Label.Container),
                "6A8F4027-012B-4B9D-92A4-86B10592F91C" => new TypedPrincipal("6A8F4027-012B-4B9D-92A4-86B10592F91C",
                    Label.Container),
                "DFD3D99B-7F86-4094-9BD4-FFA22CA9BBD4" => new TypedPrincipal("DFD3D99B-7F86-4094-9BD4-FFA22CA9BBD4",
                    Label.Container),
                "7BE126D8-9F89-4D1F-A569-5856BDA90BB4" => new TypedPrincipal("7BE126D8-9F89-4D1F-A569-5856BDA90BB4",
                    Label.Container),
                "A0772FA7-1275-4FEE-9F81-A05FF4EA4C04" => new TypedPrincipal("A0772FA7-1275-4FEE-9F81-A05FF4EA4C04",
                    Label.Container),
                "AA6238BE-9DDB-4AC7-BC2F-AF64BDD1A2C9" => new TypedPrincipal("AA6238BE-9DDB-4AC7-BC2F-AF64BDD1A2C9",
                    Label.Container),
                "493FD999-0DD9-438A-B047-D0D1980CB26F" => new TypedPrincipal("493FD999-0DD9-438A-B047-D0D1980CB26F",
                    Label.Container),
                "4F194344-A240-40B2-9AEB-3DC26B67D53D" => new TypedPrincipal("4F194344-A240-40B2-9AEB-3DC26B67D53D",
                    Label.Container),
                "A39832BB-FE7F-44A4-8B7D-86D09D3A219E" => new TypedPrincipal("A39832BB-FE7F-44A4-8B7D-86D09D3A219E",
                    Label.Container),
                "E12BA63E-B1FC-4457-97D5-CB8172AD6DF4" => new TypedPrincipal("E12BA63E-B1FC-4457-97D5-CB8172AD6DF4",
                    Label.Container),
                "16D38D45-9907-4B26-B4AF-804707BA0267" => new TypedPrincipal("16D38D45-9907-4B26-B4AF-804707BA0267",
                    Label.Container),
                "9F659C31-CB5C-48F6-ABD7-672CBCEE98F0" => new TypedPrincipal("9F659C31-CB5C-48F6-ABD7-672CBCEE98F0",
                    Label.Container),
                "583F4344-A6A0-4905-848A-207EFA4BC301" => new TypedPrincipal("583F4344-A6A0-4905-848A-207EFA4BC301",
                    Label.Container),
                "7A405B09-5BA5-4E21-A327-AAE11FFC6F67" => new TypedPrincipal("7A405B09-5BA5-4E21-A327-AAE11FFC6F67",
                    Label.Container),
                "DE0C2C2B-4EA6-494D-A3CF-8B53BD9C1A12" => new TypedPrincipal("DE0C2C2B-4EA6-494D-A3CF-8B53BD9C1A12",
                    Label.Container),
                "0FA31C29-05B4-40C7-979F-BF88857E6E12" => new TypedPrincipal("0FA31C29-05B4-40C7-979F-BF88857E6E12",
                    Label.Container),
                "9A6D39CC-7906-4A59-868C-884D3FBE9797" => new TypedPrincipal("9A6D39CC-7906-4A59-868C-884D3FBE9797",
                    Label.Container),
                "A27C6FE0-E3DF-4345-904F-B5E4CD6B3683" => new TypedPrincipal("A27C6FE0-E3DF-4345-904F-B5E4CD6B3683",
                    Label.Container),
                "E2142D8D-368F-42F7-A654-1B149C1F6AB1" => new TypedPrincipal("E2142D8D-368F-42F7-A654-1B149C1F6AB1",
                    Label.Container),
                "332CEFC8-64E0-44C3-A859-5D7CB35F66B9" => new TypedPrincipal("332CEFC8-64E0-44C3-A859-5D7CB35F66B9",
                    Label.Container),
                "D32AA4B9-F617-4D05-8F5A-E3D540689BDA" => new TypedPrincipal("D32AA4B9-F617-4D05-8F5A-E3D540689BDA",
                    Label.Container),
                "CF1709AD-6D01-4235-AFDC-F039BE2E17B0" => new TypedPrincipal("CF1709AD-6D01-4235-AFDC-F039BE2E17B0",
                    Label.Container),
                "28D2E770-AB20-44C9-8F06-C1D802A82538" => new TypedPrincipal("28D2E770-AB20-44C9-8F06-C1D802A82538",
                    Label.Container),
                "1F5D17E4-25F2-45EE-91F9-64695B2BD192" => new TypedPrincipal("1F5D17E4-25F2-45EE-91F9-64695B2BD192",
                    Label.Container),
                "3A4A1FDB-E148-41E4-8CB0-0002BFF56D86" => new TypedPrincipal("3A4A1FDB-E148-41E4-8CB0-0002BFF56D86",
                    Label.Container),
                "FCC6E8AE-C05E-4B9A-B775-F0BC1EE7803C" => new TypedPrincipal("FCC6E8AE-C05E-4B9A-B775-F0BC1EE7803C",
                    Label.Container),
                "E327D449-0602-4790-9A1D-8059EB1FE01F" => new TypedPrincipal("E327D449-0602-4790-9A1D-8059EB1FE01F",
                    Label.Container),
                "8D89C4BA-5FC9-40D8-AAA6-76733373A389" => new TypedPrincipal("8D89C4BA-5FC9-40D8-AAA6-76733373A389",
                    Label.Container),
                "06A78F6F-3C8B-421C-85FF-C5F6731915F2" => new TypedPrincipal("06A78F6F-3C8B-421C-85FF-C5F6731915F2",
                    Label.Container),
                "6344099A-E8F3-4EC2-8058-37DABB3541D4" => new TypedPrincipal("6344099A-E8F3-4EC2-8058-37DABB3541D4",
                    Label.Container),
                "123F6A8F-C485-4306-924B-DFC62122665B" => new TypedPrincipal("123F6A8F-C485-4306-924B-DFC62122665B",
                    Label.Container),
                "CA6588D1-EA16-4FE7-9EF8-EBA0AB2197B6" => new TypedPrincipal("CA6588D1-EA16-4FE7-9EF8-EBA0AB2197B6",
                    Label.Container),
                "BFBC5494-9DA3-471D-899F-7270A86DC9E5" => new TypedPrincipal("BFBC5494-9DA3-471D-899F-7270A86DC9E5",
                    Label.Container),
                "B1E8A738-9EB1-4268-86FA-3C117CC81A4C" => new TypedPrincipal("B1E8A738-9EB1-4268-86FA-3C117CC81A4C",
                    Label.Container),
                "021D5AC8-C2F6-43A5-9FDE-051C4378969B" => new TypedPrincipal("021D5AC8-C2F6-43A5-9FDE-051C4378969B",
                    Label.Container),
                "5CFACC5D-615D-4B74-A395-90D1593D9E28" => new TypedPrincipal("5CFACC5D-615D-4B74-A395-90D1593D9E28",
                    Label.Container),
                "7D4F9527-93FE-4E61-AB42-83B6175B64BA" => new TypedPrincipal("7D4F9527-93FE-4E61-AB42-83B6175B64BA",
                    Label.Container),
                "996A0AA0-402A-4DBD-A36A-81547D868791" => new TypedPrincipal("996A0AA0-402A-4DBD-A36A-81547D868791",
                    Label.Container),
                "74FFA077-C0AF-4C29-843E-B3EB220F5746" => new TypedPrincipal("74FFA077-C0AF-4C29-843E-B3EB220F5746",
                    Label.Container),
                "50229EAB-26F2-47B6-B420-3AA7B3276B2B" => new TypedPrincipal("50229EAB-26F2-47B6-B420-3AA7B3276B2B",
                    Label.Container),
                "88180019-BC96-4AE9-8095-1C169AEE9CFC" => new TypedPrincipal("88180019-BC96-4AE9-8095-1C169AEE9CFC",
                    Label.Container),
                "00419CEC-BA33-4329-A108-C43B87857292" => new TypedPrincipal("00419CEC-BA33-4329-A108-C43B87857292",
                    Label.Container),
                "3C5B360B-1691-485B-8B0C-0F5476669D73" => new TypedPrincipal("3C5B360B-1691-485B-8B0C-0F5476669D73",
                    Label.Container),
                "213D6B0F-3797-4246-95C8-47103DEC6899" => new TypedPrincipal("213D6B0F-3797-4246-95C8-47103DEC6899",
                    Label.Container),
                "FC5FE752-0D68-4530-9AC7-0360258CB311" => new TypedPrincipal("FC5FE752-0D68-4530-9AC7-0360258CB311",
                    Label.Container),
                "85785E45-9608-4178-A51A-9B5E3D6F3BC4" => new TypedPrincipal("85785E45-9608-4178-A51A-9B5E3D6F3BC4",
                    Label.Container),
                "FEE04CB0-909D-4664-82E7-18D34B2980C8" => new TypedPrincipal("FEE04CB0-909D-4664-82E7-18D34B2980C8",
                    Label.Container),
                "613495F6-A0CE-4511-8ABF-8131BC6CC5E3" => new TypedPrincipal("613495F6-A0CE-4511-8ABF-8131BC6CC5E3",
                    Label.Container),
                "C187A53B-5708-409E-B32F-5E3A22B9BCEE" => new TypedPrincipal("C187A53B-5708-409E-B32F-5E3A22B9BCEE",
                    Label.Container),
                "97F24DE9-7F06-4632-B221-B02190CFC1BC" => new TypedPrincipal("97F24DE9-7F06-4632-B221-B02190CFC1BC",
                    Label.Container),
                "7BCA5B91-2ACA-433F-99D1-FA896D09881B" => new TypedPrincipal("7BCA5B91-2ACA-433F-99D1-FA896D09881B",
                    Label.Container),
                "C42E91AD-39E6-49D4-8A23-8CF0D4423427" => new TypedPrincipal("C42E91AD-39E6-49D4-8A23-8CF0D4423427",
                    Label.Container),
                "B02EB370-37B0-4134-B0A8-187E74E9E5EE" => new TypedPrincipal("B02EB370-37B0-4134-B0A8-187E74E9E5EE",
                    Label.Container),
                "1B647D1D-0D47-4348-9C22-4ED52B4D077F" => new TypedPrincipal("1B647D1D-0D47-4348-9C22-4ED52B4D077F",
                    Label.Container),
                "6CF3CB32-8354-4983-B563-8012F1BB0EC2" => new TypedPrincipal("6CF3CB32-8354-4983-B563-8012F1BB0EC2",
                    Label.Container),
                "083E8017-B5E7-4433-8883-94A691020C70" => new TypedPrincipal("083E8017-B5E7-4433-8883-94A691020C70",
                    Label.Container),
                "9A97A778-C3A9-4581-BA0E-C9110D8CFD45" => new TypedPrincipal("9A97A778-C3A9-4581-BA0E-C9110D8CFD45",
                    Label.Container),
                "D5D6B5FC-BA30-4332-9976-BF83276222FF" => new TypedPrincipal("D5D6B5FC-BA30-4332-9976-BF83276222FF",
                    Label.Container),
                "AF9AFE30-4585-4B03-8D97-7B33B496E09B" => new TypedPrincipal("AF9AFE30-4585-4B03-8D97-7B33B496E09B",
                    Label.Container),
                "46E29A49-0278-4B70-A23D-FBF21BCC36E7" => new TypedPrincipal("46E29A49-0278-4B70-A23D-FBF21BCC36E7",
                    Label.Container),
                "B3EC44D7-7FED-4D9C-AAEF-48C9FE98DB16" => new TypedPrincipal("B3EC44D7-7FED-4D9C-AAEF-48C9FE98DB16",
                    Label.Container),
                "7C567DFA-5D61-4B92-81E4-F7A970B9BFDC" => new TypedPrincipal("7C567DFA-5D61-4B92-81E4-F7A970B9BFDC",
                    Label.Container),
                "S-1-5-9" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-9", Label.Group),
                "B075DB24-5B1D-4187-BB42-00057CB2EDFD" => new TypedPrincipal("B075DB24-5B1D-4187-BB42-00057CB2EDFD",
                    Label.Container),
                "S-1-5-21-3130019616-2776909439-2417379446-1102" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-1102", Label.Group),
                "17752E77-3D50-472E-B37A-074CDC6EDD71" => new TypedPrincipal("17752E77-3D50-472E-B37A-074CDC6EDD71",
                    Label.Container),
                "2043A562-9736-4D37-ACBF-66DF111A3AF5" => new TypedPrincipal("2043A562-9736-4D37-ACBF-66DF111A3AF5",
                    Label.Container),
                "D5CD4A98-6858-424F-AB3C-9152031F5382" => new TypedPrincipal("D5CD4A98-6858-424F-AB3C-9152031F5382",
                    Label.Container),
                "00421F2D-9369-44B5-AFD4-683E15287F58" => new TypedPrincipal("00421F2D-9369-44B5-AFD4-683E15287F58",
                    Label.Container),
                "3E0CF950-841E-41A5-806C-C8F7BC969759" => new TypedPrincipal("3E0CF950-841E-41A5-806C-C8F7BC969759",
                    Label.Container),
                "41504172-85F5-4C5A-9A7F-8AFD7AF9D502" => new TypedPrincipal("41504172-85F5-4C5A-9A7F-8AFD7AF9D502",
                    Label.Container),
                "91781CFB-7806-4B3D-924E-2D76CA5E8CD9" => new TypedPrincipal("91781CFB-7806-4B3D-924E-2D76CA5E8CD9",
                    Label.Container),
                "S-1-5-21-3130019616-2776909439-2417379446-2117" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2117", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-2115" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2115", Label.User),
                "869A84DF-489B-4549-BBF9-F13346DA069A" => new TypedPrincipal("869A84DF-489B-4549-BBF9-F13346DA069A",
                    Label.Container),
                "AF7C249C-524B-479B-BFED-EA3527FAA43B" => new TypedPrincipal("AF7C249C-524B-479B-BFED-EA3527FAA43B",
                    Label.Container),
                "AC38AF0A-476A-491C-A99C-46BD7E6B1ED9" => new TypedPrincipal("AC38AF0A-476A-491C-A99C-46BD7E6B1ED9",
                    Label.Container),
                "S-1-5-21-3130019616-2776909439-2417379446-1000" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-1000", Label.Group),
                "S-1-5-32-548" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-548", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-500" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-500", Label.User),
                "S-1-5-32-545" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-545", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-513" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-513", Label.Group),
                "S-1-5-11" => new TypedPrincipal("S-1-5-11", Label.Group),
                "S-1-5-4" => new TypedPrincipal("S-1-5-4", Label.Group),
                "S-1-5-32-546" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-546", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-514" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-514", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-501" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-501", Label.User),
                "S-1-5-32-550" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-550", Label.Group),
                "S-1-5-32-551" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-551", Label.Group),
                "S-1-5-32-552" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-552", Label.Group),
                "S-1-5-32-555" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-555", Label.Group),
                "S-1-5-32-556" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-556", Label.Group),
                "S-1-5-32-558" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-558", Label.Group),
                "S-1-5-32-559" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-559", Label.Group),
                "S-1-5-32-562" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-562", Label.Group),
                "S-1-5-32-568" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-568", Label.Group),
                "S-1-5-17" => new TypedPrincipal("S-1-5-17", Label.Group),
                "S-1-5-32-569" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-569", Label.Group),
                "S-1-5-32-573" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-573", Label.Group),
                "S-1-5-32-574" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-574", Label.Group),
                "S-1-5-32-575" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-575", Label.Group),
                "S-1-5-32-576" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-576", Label.Group),
                "S-1-5-32-577" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-577", Label.Group),
                "S-1-5-32-578" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-578", Label.Group),
                "S-1-5-32-579" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-579", Label.Group),
                "S-1-5-32-580" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-580", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-517" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-517", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-553" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-553", Label.Group),
                "S-1-5-32-549" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-549", Label.Group),
                "S-1-5-32-554" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-554", Label.Group),
                "S-1-5-32-557" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-557", Label.Group),
                "S-1-5-32-560" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-560", Label.Group),
                "S-1-5-32-561" => new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-561", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446", Label.Domain),
                "S-1-5-21-3130019616-2776909439-2417379446-498" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-498", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-516" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-516", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-2110" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2110", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-2111" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2111", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-2122" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2122", Label.User),
                "AB616901-D423-4B9A-B68F-D24CEE1E36EF" => new TypedPrincipal("AB616901-D423-4B9A-B68F-D24CEE1E36EF",
                    Label.Container),
                "0DE400CD-2FF3-46E0-8A26-2C917B403C65" => new TypedPrincipal("0DE400CD-2FF3-46E0-8A26-2C917B403C65",
                    Label.OU),
                "629289D5-75F1-4122-B30E-3D823AD0E83C" => new TypedPrincipal("629289D5-75F1-4122-B30E-3D823AD0E83C",
                    Label.Container),
                "9AC9B1D2-469D-4C28-A397-1FD3C7ED2B23" => new TypedPrincipal("9AC9B1D2-469D-4C28-A397-1FD3C7ED2B23",
                    Label.Container),
                "2A374493-816A-4193-BEFD-D2F4132C6DCA" => new TypedPrincipal("2A374493-816A-4193-BEFD-D2F4132C6DCA",
                    Label.OU),
                "ECAD920E-8EB1-4E31-A80E-DD36367F81F4" => new TypedPrincipal("ECAD920E-8EB1-4E31-A80E-DD36367F81F4",
                    Label.Container),
                "S-1-5-21-3084884204-958224920-2707782874" => new TypedPrincipal(
                    "S-1-5-21-3084884204-958224920-2707782874", Label.Domain),
                "BE91688F-1333-45DF-93E4-4D2E8A36DE2B" => new TypedPrincipal("BE91688F-1333-45DF-93E4-4D2E8A36DE2B",
                    Label.GPO),
                "F5BDDA03-0183-4F41-93A2-DCA253BE6450" => new TypedPrincipal("F5BDDA03-0183-4F41-93A2-DCA253BE6450",
                    Label.GPO),
                "B39818AF-6349-401A-AE0A-E4972F5BF6D9" => new TypedPrincipal("B39818AF-6349-401A-AE0A-E4972F5BF6D9",
                    Label.GPO),
                "S-1-5-21-3130019616-2776909439-2417379446-1105" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-1105", Label.User),
                "57DB0AB2-001D-4434-97A9-6AAF34754376" => new TypedPrincipal("57DB0AB2-001D-4434-97A9-6AAF34754376",
                    Label.GPO),
                "ACDD64D3-67B3-401F-A6CC-804B3F7B1533" => new TypedPrincipal("ACDD64D3-67B3-401F-A6CC-804B3F7B1533",
                    Label.GPO),
                "C45E9585-4932-4C03-91A8-1856869D49AF" => new TypedPrincipal("C45E9585-4932-4C03-91A8-1856869D49AF",
                    Label.GPO),
                "DF4B5337-3DF7-4504-B1B2-B5674186EE67" => new TypedPrincipal("DF4B5337-3DF7-4504-B1B2-B5674186EE67",
                    Label.GPO),
                "S-1-5-21-3130019616-2776909439-2417379446-571" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-571", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-572" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-572", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-521" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-521", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-520" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-520", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-518" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-518", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-502" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-502", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-515" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-515", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-2118" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2118", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-2116" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2116", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-522" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-522", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-525" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-525", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-1103" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-1103", Label.Group),
                "S-1-5-21-3130019616-2776909439-2417379446-2112" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2112", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-1001" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-1001", Label.Computer),
                "S-1-5-21-3130019616-2776909439-2417379446-1104" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-1104", Label.Computer),
                "S-1-5-21-3130019616-2776909439-2417379446-2106" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2106", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-2107" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2107", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-2114" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2114", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-2119" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2119", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-2121" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2121", Label.User),
                "S-1-5-21-3130019616-2776909439-2417379446-2103" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2103", Label.User),
                "45781029-28B5-4B9B-BAA6-308741A6F8C4" => new TypedPrincipal("45781029-28B5-4B9B-BAA6-308741A6F8C4",
                    Label.Container),
                "EA359D65-E573-48DF-8BF0-1B1031751729" => new TypedPrincipal("EA359D65-E573-48DF-8BF0-1B1031751729",
                    Label.Container),
                "351420A9-A4DA-451E-A439-FCC83B7289DD" => new TypedPrincipal("351420A9-A4DA-451E-A439-FCC83B7289DD",
                    Label.Container),
                "31621345-B09B-4045-9FEF-4C87F5FBE492" => new TypedPrincipal("31621345-B09B-4045-9FEF-4C87F5FBE492",
                    Label.Container),
                "696C77F5-24AF-4D4F-AE48-CE323905E84C" => new TypedPrincipal("696C77F5-24AF-4D4F-AE48-CE323905E84C",
                    Label.Container),
                "6BC79CB0-E66B-4752-ABF5-6727C336AD27" => new TypedPrincipal("6BC79CB0-E66B-4752-ABF5-6727C336AD27",
                    Label.Container),
                "EF0393C4-339D-4652-A2F3-59135EC87BB5" => new TypedPrincipal("EF0393C4-339D-4652-A2F3-59135EC87BB5",
                    Label.Container),
                "3AB5AA03-E8EA-42CD-8E2F-62060B509F88" => new TypedPrincipal("3AB5AA03-E8EA-42CD-8E2F-62060B509F88",
                    Label.Container),
                "77D4EE66-A52A-4A2B-A63E-310AE7405780" => new TypedPrincipal("77D4EE66-A52A-4A2B-A63E-310AE7405780",
                    Label.Container),
                "A0033396-AA37-4A14-99B2-3F2E7273D77E" => new TypedPrincipal("A0033396-AA37-4A14-99B2-3F2E7273D77E",
                    Label.Container),
                "54B2CF93-86A8-4DED-B20B-BDFAAE0D6020" => new TypedPrincipal("54B2CF93-86A8-4DED-B20B-BDFAAE0D6020",
                    Label.Container),
                "53921E98-3004-4285-858D-C901F2D1C242" => new TypedPrincipal("53921E98-3004-4285-858D-C901F2D1C242",
                    Label.Container),
                "E986A16E-91DD-4964-8C23-17CC5C33071D" => new TypedPrincipal("E986A16E-91DD-4964-8C23-17CC5C33071D",
                    Label.Container),
                "1663A808-69CC-4653-BA67-62635BDCC504" => new TypedPrincipal("1663A808-69CC-4653-BA67-62635BDCC504",
                    Label.Container),
                "C8F2C713-3DB8-4DE3-B6CD-F07C2F712A0D" => new TypedPrincipal("C8F2C713-3DB8-4DE3-B6CD-F07C2F712A0D",
                    Label.Container),
                "80C5D5D6-B1F3-47BC-BE3A-AA5CE922CA9B" => new TypedPrincipal("80C5D5D6-B1F3-47BC-BE3A-AA5CE922CA9B",
                    Label.Container),
                "87594131-09D5-4F8F-87D4-E350F04AEC3E" => new TypedPrincipal("87594131-09D5-4F8F-87D4-E350F04AEC3E",
                    Label.Container),
                "C011E11D-13DC-4C49-9D99-55A8B26465E1" => new TypedPrincipal("C011E11D-13DC-4C49-9D99-55A8B26465E1",
                    Label.Container),
                "D09245F3-7CFB-4F62-9EA1-14CFE88FDA05" => new TypedPrincipal("D09245F3-7CFB-4F62-9EA1-14CFE88FDA05",
                    Label.Container),
                "3509C504-9CD1-497E-A0F7-F1A4D63BDF39" => new TypedPrincipal("3509C504-9CD1-497E-A0F7-F1A4D63BDF39",
                    Label.Container),
                "FF0D453E-352C-492B-94FE-3C39D8D1757E" => new TypedPrincipal("FF0D453E-352C-492B-94FE-3C39D8D1757E",
                    Label.Container),
                "85C7EE7C-BD32-4FA7-84C7-9EC0D5723715" => new TypedPrincipal("85C7EE7C-BD32-4FA7-84C7-9EC0D5723715",
                    Label.Container),
                "6AF2CC1A-FD7F-4C19-8E66-67225F596DA7" => new TypedPrincipal("6AF2CC1A-FD7F-4C19-8E66-67225F596DA7",
                    Label.Container),
                "35F5902B-2DDE-46A4-A4BE-13E19AEBA3AC" => new TypedPrincipal("35F5902B-2DDE-46A4-A4BE-13E19AEBA3AC",
                    Label.Container),
                "36DD5C9E-0FCA-404A-8C48-E1627438D125" => new TypedPrincipal("36DD5C9E-0FCA-404A-8C48-E1627438D125",
                    Label.Container),
                "D7E6ABCF-4EE2-40E3-8D1B-6F6222F68ADF" => new TypedPrincipal("D7E6ABCF-4EE2-40E3-8D1B-6F6222F68ADF",
                    Label.Container),
                "S-1-5-21-3130019616-2776909439-2417379446-2105" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2105", Label.Computer),
                "S-1-5-21-3130019616-2776909439-2417379446-2120" => new TypedPrincipal(
                    "S-1-5-21-3130019616-2776909439-2417379446-2120", Label.Computer),
                _ => throw new ArgumentOutOfRangeException(nameof(id), id, null)
            };

            return principal;
        }

        public Label LookupSidType(string sid, string domain)
        {
            var result = ResolveIDAndType(sid, domain);
            return result.ObjectType;
        }

        public Label LookupGuidType(string guid, string domain)
        {
            var result = ResolveIDAndType(guid, domain);
            return result.ObjectType;
        }

        public string GetDomainNameFromSid(string sid)
        {
            throw new System.NotImplementedException();
        }

        public Task<string> GetSidFromDomainName(string domainName)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<string> DoRangedRetrieval(string distinguishedName, string attributeName)
        {
            throw new System.NotImplementedException();
        }

        public Task<string> ResolveHostToSid(string hostname, string domain)
        {
            throw new System.NotImplementedException();
        }

        public Task<TypedPrincipal> ResolveAccountName(string name, string domain)
        {
            throw new System.NotImplementedException();
        }

        public TypedPrincipal ResolveDistinguishedName(string dn)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<SearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope, string[] props, CancellationToken cancellationToken,
            string domainName = null, bool includeAcl = false, bool showDeleted = false, string adsPath = null,
            bool globalCatalog = false, bool skipCache = false)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<SearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope, string[] props, string domainName = null,
            bool includeAcl = false, bool showDeleted = false, string adsPath = null, bool globalCatalog = false,
            bool skipCache = false)
        {
            throw new System.NotImplementedException();
        }

        public Forest GetForest(string domainName = null)
        {
            return _forest;
        }
    }
}