# n_queens.py

def print_board(board):
    """Display the chessboard."""
    for row in board:
        print(" ".join("Q" if cell == 1 else "." for cell in row))
    print("\n")


def is_safe(board, row, col, n):
    """Check if a queen can be placed safely at board[row][col]."""

    # Check column
    for i in range(row):
        if board[i][col] == 1:
            return False

    # Check upper-left diagonal
    i, j = row - 1, col - 1
    while i >= 0 and j >= 0:
        if board[i][j] == 1:
            return False
        i -= 1
        j -= 1

    # Check upper-right diagonal
    i, j = row - 1, col + 1
    while i >= 0 and j < n:
        if board[i][j] == 1:
            return False
        i -= 1
        j += 1

    return True


def solve_n_queens(board, row, n):
    """Use backtracking to place queens row by row."""
    if row == n:
        print_board(board)
        return True  # Found a valid arrangement

    res = False
    for col in range(n):
        if is_safe(board, row, col, n):
            # Place queen
            board[row][col] = 1

            # Recur to place rest
            res = solve_n_queens(board, row + 1, n) or res

            # Backtrack
            board[row][col] = 0

    return res


def n_queens(n):
    """Initialize board and start solving."""
    board = [[0] * n for _ in range(n)]
    if not solve_n_queens(board, 0, n):
        print("No solution exists for N =", n)
    else:
        print(f"All solutions for N = {n} are shown above.")


if __name__ == "__main__":
    n = int(input("Enter number of queens (N): "))
    n_queens(n)
