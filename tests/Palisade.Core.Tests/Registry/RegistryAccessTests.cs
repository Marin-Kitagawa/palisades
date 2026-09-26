// Hardentools
// Copyright (C) 2017-2023 Security Without Borders
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Tests.Registry;

public class RegistryAccessTests
{
    [Fact]
    public void Opens_a_real_key_read_only_when_integration_access_is_enabled()
    {
        // Gated: the normal suite must never touch the real registry. Set
        // PALISADE_INTEGRATION=1 to run this against the machine it is executing on.
        if (Environment.GetEnvironmentVariable("PALISADE_INTEGRATION") != "1")
        {
            return;
        }

        using var key = new RegistryAccess().OpenKey(RegistryRoot.CurrentUser, @"Software", false);
        Assert.NotNull(key);
    }

    [Fact]
    public void Returns_null_for_a_missing_key()
    {
        // Safe unconditionally: it asserts absence, and the key name is one this project
        // never creates.
        Assert.Null(new RegistryAccess().OpenKey(
            RegistryRoot.CurrentUser, @"Software\Palisade\NoSuchKey_9F2C", writable: false));
    }
}
