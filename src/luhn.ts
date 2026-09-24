/**
 * Luhn algorithm check (ISO/IEC 7812-1) for credit card numbers.
 *
 * Doubles every second digit from the right, sums the resulting digits
 * (subtracting 9 from any doubled value > 9), and validates that the total
 * is divisible by 10. Non-digit characters are ignored.
 */
export function isLuhnValid(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    double = !double;
  }

  return sum % 10 === 0;
}
