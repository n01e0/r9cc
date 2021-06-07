int prime(int n) {
  if (n % 2 == 0) return 0;
  int k = 3;
  while (k * k <= n) {
    if (n % k == 0)
      return 0;
    k = k + 2;
  }
  return 1;
}

int main() {
  int i = 2;
  int count = 0;
  while (1) {
    if (prime(i))
      count++;
    i++;
    if (count == 1000000) {
        printf("%d\n", i);
        break;
    }
  }
  return 0;
}
