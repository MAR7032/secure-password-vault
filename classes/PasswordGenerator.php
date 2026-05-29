<?php

declare(strict_types=1);

class PasswordGenerator
{
    private const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    private const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const NUMBERS = '0123456789';
    private const SPECIAL = '!@#$%&*?.';

    public function generate(
        int $length,
        int $lowercaseCount,
        int $uppercaseCount,
        int $numberCount,
        int $specialCount
    ): string {
        if ($length < 4 || $length > 100) {
            throw new InvalidArgumentException(
                'Password length must be between 4 and 100 characters.'
            );
        }

        $totalSelected = $lowercaseCount
            + $uppercaseCount
            + $numberCount
            + $specialCount;

        if ($totalSelected !== $length) {
            throw new InvalidArgumentException(
                'The character quantities must equal the total length.'
            );
        }

        if (
            $lowercaseCount < 0 ||
            $uppercaseCount < 0 ||
            $numberCount < 0 ||
            $specialCount < 0
        ) {
            throw new InvalidArgumentException(
                'Character quantities cannot be negative.'
            );
        }

        $characters = [];

        $this->addRandomCharacters(
            $characters,
            self::LOWERCASE,
            $lowercaseCount
        );

        $this->addRandomCharacters(
            $characters,
            self::UPPERCASE,
            $uppercaseCount
        );

        $this->addRandomCharacters(
            $characters,
            self::NUMBERS,
            $numberCount
        );

        $this->addRandomCharacters(
            $characters,
            self::SPECIAL,
            $specialCount
        );

        $this->secureShuffle($characters);

        return implode('', $characters);
    }

    private function addRandomCharacters(
        array &$characters,
        string $characterSet,
        int $quantity
    ): void {
        $maximumIndex = strlen($characterSet) - 1;

        for ($position = 0; $position < $quantity; $position++) {
            $randomIndex = random_int(0, $maximumIndex);
            $characters[] = $characterSet[$randomIndex];
        }
    }

    private function secureShuffle(array &$characters): void
    {
        for ($position = count($characters) - 1; $position > 0; $position--) {
            $randomPosition = random_int(0, $position);

            $temporaryCharacter = $characters[$position];
            $characters[$position] = $characters[$randomPosition];
            $characters[$randomPosition] = $temporaryCharacter;
        }
    }
}