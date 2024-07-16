using System;
using System.Collections.Generic;
using CommonLibTest.Facades;
using Microsoft.VisualBasic;
using SharpHoundCommonLib;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest {
    public class DirectoryObjectInterfaceTests {
        private IDirectoryObject _directoryObject;

        public DirectoryObjectInterfaceTests(IDirectoryObject directoryObject) {
            _directoryObject = directoryObject;
        }

        [Fact]
        public void Test_TryGetDistinquishedName() {
            var success = _directoryObject.TryGetDistinguishedName(out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetProperty() {
            var success = _directoryObject.TryGetProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetByteProperty() {
            var success = _directoryObject.TryGetByteProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetArrayProperty() {
            var success = _directoryObject.TryGetArrayProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetByteArrayProperty() {
            var success = _directoryObject.TryGetByteArrayProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetIntProperty() {
            var success = _directoryObject.TryGetIntProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetCertificateArrayProperty() {
            var success = _directoryObject.TryGetCertificateArrayProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetSecurityIdentifier() {
            var success = _directoryObject.TryGetSecurityIdentifier("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_TryGetGuid() {
            var success = _directoryObject.TryGetGuid("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_GetProperty() {
            var success = _directoryObject.GetProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_GetByteProperty() {
            var success = _directoryObject.GetByteProperty("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_PropertyCount() {
            var success = _directoryObject.PropertyCount("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }

        [Fact]
        public void Test_PropertyNames() {
            var success = _directoryObject.PropertyNames("", out var val);
            Assert.True(success);
            Assert.NotNull(val);
        }
    }
}