#include "include/ChaCha_round.h"
#include "../include/ChaCha.h"

void ChaCha_Rounds(uint32_t *State, ChaCha_Round_Count_t NumRounds) {

    int Round;

    for (Round = 0; Round < (int)NumRounds; Round++) {
        ChaCha_Round(State);
    }

    return;
}

void ChaCha_Round(uint32_t *State) {

    ChaCha_OddRound(State);
    ChaCha_EvenRound(State);

    return;
}

void ChaCha_OddRound(uint32_t *State) {

    ChaCha_QuarterRound(&(State[0]), &(State[4]), &(State[8]), &(State[12]));
    ChaCha_QuarterRound(&(State[1]), &(State[5]), &(State[9]), &(State[13]));
    ChaCha_QuarterRound(&(State[2]), &(State[6]), &(State[10]), &(State[14]));
    ChaCha_QuarterRound(&(State[3]), &(State[7]), &(State[11]), &(State[15]));

    return;
}

void ChaCha_EvenRound(uint32_t *State) {

    ChaCha_QuarterRound(&(State[0]), &(State[5]), &(State[10]), &(State[15]));
    ChaCha_QuarterRound(&(State[1]), &(State[6]), &(State[11]), &(State[12]));
    ChaCha_QuarterRound(&(State[2]), &(State[7]), &(State[8]), &(State[13]));
    ChaCha_QuarterRound(&(State[3]), &(State[4]), &(State[9]), &(State[14]));

    return;
}

void ChaCha_QuarterRound(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D) {

    (*A) += (*B);
    (*D) ^= (*A);
    (*D) = ChaCha_Rotate_Left((*D), 16);
    (*C) += (*D);
    (*B) ^= (*C);
    (*B) = ChaCha_Rotate_Left((*B), 12);
    (*A) += (*B);
    (*D) ^= (*A);
    (*D) = ChaCha_Rotate_Left((*D), 8);
    (*C) += (*D);
    (*B) ^= (*C);
    (*B) = ChaCha_Rotate_Left((*B), 7);

    return;
}

uint32_t ChaCha_Rotate_Left(uint32_t Word, size_t ShiftSize) {
    return (Word << ShiftSize) | (Word >> (32 - ShiftSize));
}
