#include "types.h"
#include "stat.h"
#include "user.h"

#define PNUM 5 // amount of fork process
#define PRINT_CYCLE 10000000 // cycle for print info
#define TOTAL_COUNTER 500000000 // cycle for termination

// sdebug
void sdebug_func(void)
{
	int weight = 0;
	int n, pid;
	printf(1, "start sdebug command\n"); // start sdebug_func
	
	for(n = 0; n < PNUM; n++)
	{
		weight++; // weight of each process should have different weight
		pid = fork(); // fork
		if(pid < 0) // error 
		{
			break;
		}
		if(pid == 0)
		{
			long int print_counter = PRINT_CYCLE; // PRINT_CYCLE : down to zero in while-loop
			long int start_ticks = uptime();
			long int counter = 0; // runtime counter : up to TOTAL_COUNTER in while-loop
			long int end_ticks = 0; // end ticks : for printing when arrived in PRINT_CYCLE in while-loop
			// weightset after (fork -> allocproc)
			if(weightset(weight) == -1) // error in weightset 
				exit();
			
			
			int first = 1; // print for only once
			while(counter <= TOTAL_COUNTER) // child process runtime
			{
				counter++;
				print_counter--;
				if(print_counter == 0)
				{
					if(first) // never printed in this process
					{	
						end_ticks = uptime();
						printf(1, "PID: %d, WEIGHT: %d, TIMES: %d ms\n", getpid(), weight - 1, (end_ticks - start_ticks) * 10);
						// TOTAL_COUNTER - counter
						first = 0 ; // already printed
					}
					print_counter = PRINT_CYCLE;
				}	
						
			}
			printf(1, "PID: %d terminated \n", getpid());
			exit();
		}
		
	}
	
	// wait : parent process ( forktest() )
	for(n = PNUM; n > 0; n--)
	{
    		if(wait() < 0) // wait for all process we forked
    		{
      			printf(1, "wait stopped early\n");
      			exit();
    		}
  	}
	
	printf(1, "end of sdebug command\n");
	return ; 
}

int main(void)
{
	sdebug_func();
	exit();
}
