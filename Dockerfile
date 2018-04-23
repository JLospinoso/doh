FROM quay.io/jlospinoso/cppbuild:v1.5.0
RUN apt update && apt upgrade -y

RUN mkdir doh
WORKDIR doh

COPY *.h *.hpp *.cpp *.c CMakeLists.txt ./
RUN mkdir build
WORKDIR build
RUN cmake ..
RUN make
COPY block ./block
COPY host ./host
ENTRYPOINT ["/doh/build/doh"]
