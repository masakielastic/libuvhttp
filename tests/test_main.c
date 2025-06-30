#include "acutest.h"
#include "../uvhttp.h"

void test_slice_cmp(void) {
    uvhttp_string_slice_t slice = {"hello", 5};
    TEST_CHECK(uvhttp_slice_cmp(&slice, "hello") == 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "world") != 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "HELLO") == 0); // Case-insensitive
    TEST_CHECK(uvhttp_slice_cmp(&slice, "hell") != 0);
    TEST_CHECK(uvhttp_slice_cmp(&slice, "helloo") != 0);
}

TEST_LIST = {
    { "slice/cmp", test_slice_cmp },
    { NULL, NULL }
};