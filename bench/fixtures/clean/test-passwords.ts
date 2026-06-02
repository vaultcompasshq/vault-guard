// False positive candidates: test/fixture passwords
// (path-aware severity should downgrade these even if not fully suppressed)
describe("auth", () => {
  const password = "testPassword1234";
  const adminPass = "Admin1234!";
  it("should hash passwords", () => {
    expect(hash(password)).toBeDefined();
  });
});
