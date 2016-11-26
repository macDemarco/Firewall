class LFSR:
    
    def __init__(self, initial_state, hardwiring):
        if len(initial_state) != len(hardwiring):
            raise ValueError("initial_state and hardwiring must have the same length")
        self.stages_num = len(initial_state)
        self.state = initial_state
        self.hardwiring = hardwiring
        
    def step(self):
        '''
        Makes a step by calculating the feedback bit and shifting.
        '''
        feedback_bit = 0
        for i in range(0, self.stages_num):
            feedback_bit += self.hardwiring[i] * self.state[i]
        feedback_bit = feedback_bit % 2
        self.state = self.state[1:] + [feedback_bit]
        
    def output(self, bits_num):
        ''' 
        Prints the first bits_num bits of the output.
        '''
        print("First " + str(bits_num) + " bits:") 
        for j in range(bits_num):
            print(self.state[0], end = " ")
            self.step()
        print()
        
    def printPeriod(self):
        '''
        Prints the number of steps it takes until an internal state is repeated.
        '''
        states = dict()
        i = 0
        while True:
            states[str(self.state)] = True
            self.step()
            i += 1
            if str(self.state) in states:
                print("The period is " + str(i) + " steps.")
                return            
           

def main():
    print("LFSR1:")
    initial_state = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    hardwiring = [1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    LFSR1 = LFSR(initial_state, hardwiring)
    LFSR1.output(30)
    LFSR1.printPeriod()
    
    print("\nLFSR2:")
    hardwiring = [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    LFSR2 = LFSR(initial_state, hardwiring)
    LFSR2.output(30)
    LFSR2.printPeriod()
    
if __name__ == "__main__":
    main()