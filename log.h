#ifndef LOG_H
#define LOG_H

bool init_log( const char * file_name, bool flush );
int get_log_fd();
void close_log();

#endif // LOG_H
