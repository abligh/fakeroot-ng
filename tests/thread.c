#include <stdio.h>

#include <sys/types.h>

#include <unistd.h>
#include <pthread.h>

void *thread_sub( void *param )
{
    printf("child uid=%d\n", getuid() );

    return 0;
}

int main(int argc, char *argv[])
{
    pthread_t thread;

    int err=pthread_create( &thread, NULL, thread_sub, 0 );

    if( err==0 ) {
        printf("Parent uid=%d\n", getuid() );
    } else {
        printf("Thread creationg error: %d\n", err );

        return 1;
    }

    pthread_join( thread, NULL );

    printf("Parent: child thread exit\n");

    return 0;
}
